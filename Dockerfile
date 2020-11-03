FROM python:3.9.0-slim
WORKDIR /app
COPY art /app/art/
COPY environmentvalues.py mrr_checker.py wowhoneypot.py /app/
RUN mkdir /app/log && useradd --no-create-home --base-dir /app -u 1000 app && chown -R app:app /app
USER app
CMD ["./wowhoneypot.py"]
