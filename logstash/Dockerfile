FROM docker.elastic.co/logstash/logstash:8.12.0

# Remove configurações padrão e copia o nosso pipeline estrito
RUN rm -f /usr/share/logstash/pipeline/logstash.conf
COPY logstash.conf /usr/share/logstash/pipeline/logstash.conf