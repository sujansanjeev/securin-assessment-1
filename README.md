
# CVE Management System

A full-stack web application that allows users to view and interact with CVE (Common Vulnerabilities and Exposures) data. This project includes both a frontend built with React and a backend built with Flask, using TinyDB to store and serve CVE data.

---

## Features

- View a list of CVEs with pagination.
- Filter CVEs by year, CVSS score, or last modified date.
- Display detailed information for each CVE, including its description, CVSS v2/v3 metrics, and CPE data.
- Automatic fetching and updating of CVE data from the NVD (National Vulnerability Database) API.

---

## Installation

### Prerequisites

Before you begin, ensure that you have the following installed:

- **Node.js** (for the frontend)
- **Python 3.x** (for the backend)
- **pip** (for installing Python packages)
- **Flask** and **TinyDB** (for the backend)
- **CORS** library for cross-origin requests

### Backend Installation

1. Clone the repository:

   ```bash
   [git clone https://github.com/sujansanjeev/securin-assessment-1.git]
   cd securin-assessment-1
   ```

2. Navigate to the backend directory and set up a virtual environment (optional but recommended):

   ```bash
   cd backend
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required dependencies:

   ```bash
   pip install flask tinydb flask_cors flask_sqlalchemy
   ```

4. Start the Flask backend server:

   ```bash
   python app.py
   ```

   The Flask server should now be running on `http://localhost:5000`.

5. **Background Task**: The backend will automatically fetch and update CVE data from the NVD API every 24 hours in the background.

---

### Frontend Installation

1. Navigate to the frontend directory:

   ```bash
   cd frontend
   ```

2. Install the required Node.js dependencies:

   ```bash
   npm install
   ```

3. Start the React development server:

   ```bash
   npm start
   ```

   The React frontend should now be running on `http://localhost:3000`.

---

## Usage

Once both the backend and frontend are up and running, you can interact with the CVE Management System via the web browser:

### CVE List Page

- View a paginated list of CVEs fetched from the NVD.
- Filter CVEs by year, CVSS score, and last modified date.
- Click on a CVE entry to view its detailed information.

### CVE Detail Page

- View detailed information about a selected CVE, including:
  - Description
  - CVSS v2/v3 metrics (base score and vector string)
  - CPE (Common Platform Enumeration) data indicating the affected software/hardware.

---

## Backend API

The backend exposes two main endpoints:

### 1. `/api/cves`

- **Method**: `GET`
- **Parameters**:
  - `page`: Page number for pagination (default: 1)
  - `per_page`: Number of results per page (default: 10)
  - `year`: Filter by CVE year
  - `score`: Filter by CVSS score
  - `modified_days`: Filter by CVE's last modified date (in days)
  - `sort_by`: Sort results by a field (e.g., `published_date`)
  - `sort_order`: Sort order (`asc` or `desc`)

### 2. `/api/cves/<cve_id>`

- **Method**: `GET`
- **Parameters**:
  - `cve_id`: The unique identifier of the CVE to fetch details for.

---

## Contributing

If you'd like to contribute to this project:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to your forked repository (`git push origin feature-name`).
5. Submit a pull request.

---
##output

<img width="1470" alt="details output" src="https://github.com/user-attachments/assets/ecd1d318-0171-49a6-8244-3658705ea1a1" />
<img width="1470" alt="list output" src="https://github.com/user-attachments/assets/18d58745-7931-451a-8367-261ff3b6d3f5" />


## License

This project is open-source and available under the MIT License.

---

## Acknowledgements

- The CVE data is fetched from the [National Vulnerability Database](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-53.pdf).
- The frontend is built using [React](https://reactjs.org/).
- The backend is powered by [Flask](https://flask.palletsprojects.com/).
- Data is stored using [TinyDB](https://tinydb.readthedocs.io/en/latest/).

---

### Notes:

1. **Backend Caching**: The backend fetches CVE data from the NVD API periodically (every 24 hours), so data updates are not real-time but rather once a day.
2. **Pagination and Filtering**: The frontend supports pagination and various filters for the CVE list, and the backend supports filtering and sorting by various attributes.
