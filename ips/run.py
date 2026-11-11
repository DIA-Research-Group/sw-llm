"""Runner de experimentos: matriz configuracoes x cenarios x repeticoes.

    python -m ips.run experiments/ablation.yaml --list
    python -m ips.run experiments/ablation.yaml                 # tudo, retomando
    python -m ips.run experiments/ablation.yaml --only baseline,+shadow --scenarios zap --reps 3

Cada execucao fica em ``runs/<experimento>/<config>/<cenario>/rep-NN/`` com a
configuracao efetiva, metadados de ambiente (commit, digests das imagens),
eventos do detector e amostras de recursos. Execucoes concluidas (arquivo
``DONE``) sao puladas, entao o comando pode ser interrompido e retomado.

A ordem das execucoes e embaralhada dentro de cada repeticao (semente fixa)
para que derivas temporais (latencia da API, carga da maquina) nao se
confundam com o efeito de uma configuracao.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import time
from typing import Any

import yaml

from ips import scenarios as sc
from ips.config import Experiment, RunSpec, dump_json
from ips.enforcement import HEADER

log = logging.getLogger("ips.run")
PROJECT = "ips-lab"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def compose(*args: str, env: dict[str, str] | None = None, files: list[str] | None = None,
            check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-p", PROJECT]
    for f in files or ["docker-compose.yml"]:
        cmd += ["-f", f]
    cmd += list(args)
    full_env = {**os.environ, **(env or {})}
    log.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, env=full_env, check=check, text=True,
                          capture_output=capture)


def all_down(files: list[str] | None = None) -> None:
    compose("--profile", "*", "down", "--remove-orphans", "--timeout", "10", check=False, capture=True, files=files)


def wait_http(url: str, timeout_s: float = 240, host: str | None = None) -> None:
    """Espera o alvo responder sem erro de gateway (o Nginx sobe antes do backend)."""
    import requests

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=3, headers={"Host": host} if host else None).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise TimeoutError(f"{url} nao respondeu")


def wait_file(path: str, timeout_s: float, container: str) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if os.path.exists(path):
            return
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", container],
                               capture_output=True, text=True).stdout.strip()
        if state == "false":
            raise RuntimeError(f"{container} terminou antes de ficar pronto (ver detector.log)")
        time.sleep(1)
    raise TimeoutError(f"{path} nao apareceu")


def image_digests() -> dict[str, str]:
    out = subprocess.run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
                          "--format", "{{.Names}}\t{{.Image}}"], capture_output=True, text=True).stdout
    digests = {}
    for line in out.splitlines():
        name, image = line.split("\t")
        ref = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                             capture_output=True, text=True).stdout.strip()
        digests[name] = f"{image} ({ref})"
    return digests


def dataset_hashes(globs: tuple[str, ...]) -> dict[str, str]:
    """SHA-256 dos arquivos de dataset usados (correcao 5: versao exata registrada)."""
    import glob as _glob
    import hashlib

    out = {}
    for pattern in globs:
        for f in sorted(_glob.glob(os.path.join(ROOT, pattern))):
            h = hashlib.sha256()
            with open(f, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            out[os.path.relpath(f, ROOT)] = h.hexdigest()
    return out


def save_logs(container: str, path: str) -> None:
    with open(path, "w") as fh:
        subprocess.run(["docker", "logs", container], stdout=fh, stderr=subprocess.STDOUT)


class Runner:
    def __init__(self, exp: Experiment, exp_path: str, out_root: str, tag: str | None = None):
        self.exp = exp
        self.exp_path = exp_path
        self.out_root = out_root
        self.exp_name = f"{exp.name}-{tag}" if tag else exp.name

    def plan(self, only: set[str] | None, scenarios: list[str] | None, reps: int | None) -> list[tuple[RunSpec, str, int]]:
        specs = [s for s in self.exp.runs() if not only or s.name in only]
        if only and len(specs) != len(only):
            missing = only - {s.name for s in specs}
            raise SystemExit(f"Configuracoes inexistentes: {sorted(missing)}")
        scen = scenarios or self.exp.scenarios
        for s in scen:
            sc.get(s)
        jobs = []
        for rep in range(1, (reps or self.exp.repetitions) + 1):
            block = [(spec, s, rep) for spec in specs for s in scen]
            random.Random(self.exp.seed * 1000 + rep).shuffle(block)
            jobs.extend(block)
        return jobs

    def run_dir(self, spec: RunSpec, scenario: str, rep: int) -> str:
        return os.path.join(self.out_root, self.exp_name, spec.name, scenario, f"rep-{rep:02d}")

    # ------------------------------------------------------------------
    def execute(self, spec: RunSpec, scenario_name: str, rep: int, overrides: dict[str, Any]) -> None:
        scenario = sc.get(scenario_name)
        rdir = self.run_dir(spec, scenario_name, rep)
        if os.path.exists(os.path.join(rdir, "DONE")):
            log.info("pulando %s (concluido)", rdir)
            return
        if os.path.isdir(rdir):
            shutil.rmtree(rdir)  # execucao anterior incompleta
        os.makedirs(rdir)
        rel = os.path.relpath(rdir, ROOT)

        proxy = spec.environment.get("proxy", "nginx")
        cfg = spec.detector_config(output_dir=rel, **overrides)
        if cfg.pipeline == "observe":
            cfg.knowledge_graph = False
        dump_json(os.path.join(rdir, "detector_config.json"), cfg.to_dict())

        profiles = ["proxy-nginx", *(["proxy-crs"] if proxy == "crs" else []), "detector",
                    "redis" if cfg.log_buffer == "redis" else "es", *scenario.profiles]
        if scenario.benign:
            profiles.append("benign")
        if cfg.knowledge_graph and cfg.kg_backend == "neo4j":
            profiles.append("kg")
        env = {
            "COMPOSE_PROFILES": ",".join(profiles),
            "LOG_BUFFER": cfg.log_buffer,
            "PROXY_BACKEND": "crs" if proxy == "crs" else "juice",
            "IPS_CONFIG": os.path.join(rel, "detector_config.json"),
            "CRS_PARANOIA": str(spec.environment.get("crs_paranoia", 1)),
            "HOST_UID": str(os.getuid()), "HOST_GID": str(os.getgid()),
            "DOCKER_GID": str(os.stat("/var/run/docker.sock").st_gid),
            **scenario.env,
        }
        files = ["docker-compose.yml"]
        resources = {**self.exp.resources, **(spec.environment.get("resources") or {})}
        if resources:
            override = {"services": {svc: {"deploy": {"resources": {"limits": lim}}} for svc, lim in resources.items()}}
            opath = os.path.join(rdir, "compose.override.yml")
            with open(opath, "w") as fh:
                yaml.safe_dump(override, fh)
            files.append(os.path.relpath(opath, ROOT))

        meta: dict[str, Any] = {
            "experiment": self.exp_name, "config": spec.name, "factors": spec.factors, "scenario": scenario_name,
            "rep": rep, "environment": spec.environment, "profiles": profiles, "warmup_s": self.exp.warmup_s,
            "duration_s": self.exp.duration_s, "resources": resources,
            "datasets": dataset_hashes(scenario.datasets),
        }
        if scenario.datasets and not meta["datasets"]:
            raise RuntimeError(f"cenario {scenario_name} exige dataset (ver datasets/README.md)")
        log.info("=== %s | %s | rep %d ===", spec.name, scenario_name, rep)
        all_down(files)
        with open(os.path.join(ROOT, "blocklist.conf"), "w") as fh:
            fh.write(HEADER)

        from ips.resources import ResourceSampler

        sampler = None
        try:
            infra = ["nginx", *(["nginx-crs"] if proxy == "crs" else []), "juice-shop", "logstash",
                     "redis" if cfg.log_buffer == "redis" else "elasticsearch", *scenario.targets]
            if "kg" in profiles:
                infra.append("neo4j")
            compose("up", "-d", "--build", *infra, env=env, files=files, capture=True)
            wait_http("http://localhost:80/")
            if "vh-solr" in scenario.targets:
                wait_http("http://localhost:80/solr/", host="solr.lab")
            meta["t_infra_ready"] = time.time()
            sampler = ResourceSampler(os.path.join(rdir, "resources.csv"), PROJECT)
            sampler.start()

            benign = list(sc.BENIGN_SERVICES) if scenario.benign else []
            if benign:
                compose("up", "-d", *benign, env=env, files=files, capture=True)
            elif cfg.log_buffer == "elasticsearch":
                # sem trafego benigno o indice so nasce com o ataque; cria um evento inicial
                import requests

                requests.get("http://localhost:80/", timeout=5)
            compose("up", "-d", "detector", env=env, files=files, capture=True)
            wait_file(os.path.join(rdir, "detector_ready"), 300, "ips-detector")
            meta["t_detector_ready"] = time.time()

            time.sleep(self.exp.warmup_s)
            meta["t_attack_start"] = time.time()
            compose("up", "-d", *scenario.attackers, env=env, files=files, capture=True)

            budget = cfg.duration_s + 600
            res = subprocess.run(["docker", "wait", "ips-detector"], capture_output=True, text=True, timeout=budget)
            meta["detector_exit_code"] = int(res.stdout.strip() or -1)
            meta["t_end"] = time.time()
        finally:
            if sampler:
                sampler.stop()
            for c in ("ips-detector", *[self._container(s) for s in scenario.attackers]):
                save_logs(c, os.path.join(rdir, f"{c}.log"))
            meta["images"] = image_digests()
            dump_json(os.path.join(rdir, "run.json"), meta)
            all_down(files)
        if meta.get("detector_exit_code") != 0:
            raise RuntimeError(f"detector terminou com codigo {meta.get('detector_exit_code')} em {rdir}")
        open(os.path.join(rdir, "DONE"), "w").close()

    @staticmethod
    def _container(service: str) -> str:
        return {"owasp-zap": "owasp-zap-attacker", "slowloris": "ips-slowloris"}.get(service, f"ips-{service}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Executa a matriz de experimentos")
    ap.add_argument("experiment")
    ap.add_argument("--list", action="store_true", help="mostra a matriz e a estimativa de tempo")
    ap.add_argument("--only", help="configuracoes (separadas por virgula)")
    ap.add_argument("--scenarios", help="cenarios (separados por virgula)")
    ap.add_argument("--reps", type=int)
    ap.add_argument("--out", default=os.path.join(ROOT, "runs"))
    ap.add_argument("--set", action="append", default=[], help="campo=valor aplicado ao detector de todas as execucoes")
    ap.add_argument("--keep-going", action="store_true", help="continua apos falha de uma execucao")
    ap.add_argument("--tag", help="sufixo do diretorio do experimento (ex.: nome do modelo)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    exp = Experiment.load(args.experiment)
    tag = args.tag.replace("/", "_").replace(":", "_") if args.tag else None
    runner = Runner(exp, args.experiment, args.out, tag)
    only = set(args.only.split(",")) if args.only else None
    scen = args.scenarios.split(",") if args.scenarios else None
    jobs = runner.plan(only, scen, args.reps)

    if args.list:
        names = []
        for spec in exp.runs():
            if not only or spec.name in only:
                names.append(spec)
        print(f"Experimento: {exp.name}")
        for spec in names:
            print(f"  {spec.name:<28} fatores={spec.factors} ambiente={spec.environment}")
        per_run = exp.warmup_s + exp.duration_s + 90
        pending = sum(not os.path.exists(os.path.join(runner.run_dir(*j), "DONE")) for j in jobs)
        print(f"Cenarios: {scen or exp.scenarios} | repeticoes: {args.reps or exp.repetitions}")
        print(f"Execucoes: {len(jobs)} (pendentes: {pending}) | estimativa: {pending * per_run / 3600:.1f} h")
        return 0

    from ips.detector import parse_set

    overrides = parse_set(args.set)
    os.makedirs(os.path.join(args.out, runner.exp_name), exist_ok=True)
    shutil.copy(args.experiment, os.path.join(args.out, runner.exp_name, "experiment.yaml"))
    failures = 0
    for i, (spec, scenario, rep) in enumerate(jobs, 1):
        log.info("[%d/%d]", i, len(jobs))
        try:
            runner.execute(spec, scenario, rep, overrides)
        except KeyboardInterrupt:
            all_down()
            raise
        except Exception as exc:
            failures += 1
            log.error("Falha em %s/%s/rep %d: %s", spec.name, scenario, rep, exc)
            if not args.keep_going:
                return 1
    log.info("Concluido (%d falhas)", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
