import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "docker", "traffic", f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_csic_reader(tmp_path):
    csv_path = tmp_path / "csic.csv"
    csv_path.write_text(
        ",Method,User-Agent,Pragma,content,classification,URL\n"
        "0,GET,Mozilla/5.0 (compatible; Konqueror/3.5),no-cache,,0,http://localhost:8080/tienda1/index.jsp HTTP/1.1\n"
        "1,POST,Mozilla/5.0 (compatible; Konqueror/3.5),no-cache,id=2&nombre=%27+OR+1%3D1,1,"
        "http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1\n"
        "2,GET,Mozilla/5.0,no-cache,,1,http://localhost:8080/tienda1/publico/caracteristicas.jsp?id=%3Cscript%3E HTTP/1.1\n"
    )
    csic = load("csic_replay")
    normal = csic.load(str(csv_path), "normal")
    attack = csic.load(str(csv_path), "anomalous")
    assert len(normal) == 1 and len(attack) == 2
    assert csic.to_request(normal[0])[:2] == ("GET", "/tienda1/index.jsp")
    method, path, body, _ = csic.to_request(attack[0])
    assert method == "POST" and path == "/tienda1/publico/anadir.jsp" and "OR" in body
    assert csic.to_request(attack[1])[1] == "/tienda1/publico/caracteristicas.jsp?id=%3Cscript%3E"
