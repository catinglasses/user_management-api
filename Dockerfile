FROM python:3.12
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
EXPOSE 8000
CMD uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
