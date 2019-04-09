# views.py

This Python script uses Python version 2 to provide a web server with an item catalog sorted by categories protected by a user registration and authentication system based on Google account authentication.

## Output

Each run of this program will load a web server listening as localhost on TCP port 8000 providing the current database of information.

## Setup

Install required modules (ex. Flask, SQLAlchemy, etc.):

### Flask

``pip install Flask`` or visit http://flask.pocoo.org/docs/1.0/installation/ for the latest installation instructions.

### SQLAlchemy

``pip install SQLAlchemy`` or visit https://docs.sqlalchemy.org/en/rel_1_2/intro.html#installation for the latest installation instructions.

### oauth2client

``pip install oauth2client`` or visit https://pypi.org/project/oauth2client/ for the latest installation instructions.

## Use

Using the system that has Python version 2, execute the following command from the directory containing the views.py Python script:

NOTE - If the catalog.db file is empty or does not exist, first run the following command:

``python lotsofitems.py``

This will create the database as catalog.db, if it does not already exists and will populate the database with an initial data set.

Run the following command to start the webserver listing on TCP port 8000.

``python views.py``

## Access

Access the website by connecting to the web server using your favorite browser pointed to http://localhost:8000

### API Access

To receive a JSON output of the categories, visit http://localhost:8000/catalog.json

To receive a JSON output of a single item, add "JSON" to the item's URI.  For example, to receive the JSON output of the Soccer Cleats, visit http://localhost:8000/catalog/Soccer/Soccer%20Cleats/JSON
