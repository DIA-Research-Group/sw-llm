FROM docker.elastic.co/logstash/logstash:8.12.0

# O pipeline e montado em tempo de execucao a partir de logstash/pipeline/,
# conforme LOG_BUFFER (elasticsearch | redis). Ver docker-compose.yml.
RUN rm -f /usr/share/logstash/pipeline/logstash.conf
