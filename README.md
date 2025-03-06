# Automated API Security Testing

## Document

- Clone the repository
- Create a `.env` file
- Make a virtualenv and install all requirements
- Create a database and add configuration to the `.env` file from `.env.example`
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
python manage.py dumpdata > api.json employee

```

# License

### Key Elements:

- **Document Section**: Lists the steps for setting up the project (cloning, virtual environment, database, etc.).
- **ERD and API Diagrams**: Includes links to images hosted on GitHub for the ERD and API documentation.
- **Requirements Setup**: Command to install required dependencies.
- **Run Command**: Command to start the Django server.
- **API URL**: Lists the URL for the main API and Redoc API documentation.
- **Data Dump**: Command to dump the project's data.
