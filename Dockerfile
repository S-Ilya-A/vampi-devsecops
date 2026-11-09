FROM python:3.11.17-alpine3.24 AS builder
RUN apk --update add bash nano g++
COPY ./requirements.txt /vampi/requirements.txt
WORKDIR /vampi
RUN pip install --no-cache-dir -r requirements.txt

# Build a fresh container, copying across files & compiled parts
FROM python:3.11.17-alpine3.24
COPY . /vampi
WORKDIR /vampi
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin
ENV vulnerable=1
ENV tokentimetolive=60

# Run as an unprivileged user (was root: Trivy AVD-DS-0002, Semgrep
# missing-user). The application only reads its files and talks to Postgres.
RUN adduser -D -H -u 10001 vampi
USER 10001

ENTRYPOINT ["python"]
CMD ["app.py"]
