# Automated API Security Testing

## Document

- Clone the repository
- Create a `.env` file
- Make a virtualenv and install all requirements
- Create a database and add configuration to the `.env` file.
- Run Django migrate commands
- Run the project with `runserver` command

---

# Project ERD Diagram

<img src="https://github.com/sakilanasrinsetu/automated_api_security_testing/blob/main/erd.png?raw=true" width="100%">

---

# Project requirement setup

```bash
pip install -r requirements.txt
```

# Project Run Command

```python
python manage.py runserver


Project API Url
Main API: http://localhost:8000
API Documentation (Redoc): http://localhost:8000/redoc/

```

# For Dump Project Data

```
python manage.py dumpdata > api.json api_scanner

```

# For ERP Diagram

```
python3 manage.py graph_models -a -g -o erd.png
```


# For Store MITRE Attack Tactic and Technique

```
python manage.py load_mitre
```


# For Store GroundTruthVulnerability

```
python manage.py add_ground_truth_vulnerabilities
```
