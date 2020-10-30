FROM python:3.9.0-slim
WORKDIR /app
RUN mkdir /app/log
COPY art /app/art/
COPY chase-url.py config.txt mrr_checker.py wowhoneypot.py /app/
CMD ["./wowhoneypot.py"]
