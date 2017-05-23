# Item-Catalog

* Project for Restuarants , storing database for new users haivng functionalty of edit item , edit resturant name , delete resturant, delete items, login thorough gmail account

# How To Run This Project On Local Machine:-

* clone or download this repository

* Download virtual box.

* Download and install Vagrant.

* Right click and open terminal in this repository 

* vagrant init in termial, it may take several minutes for vagrant to initialise.

* vagrant up && vagrant ssh.
* Now Change your current directory :- cd /vagrant
* Now Install following packages :-
+ sudo apt-get  update
+ sudo apt-get upgrade
+ sudo apt-get install postgresql python-psycopg2
+ sudo apt-get install python-sqlalchemy
+ sudo apt-get install python-pip
+ sudo pip install --upgrade pip
+ sudo pip install werkzeug==0.8.3
+ sudo pip install flask==0.9
+ sudo pip install Flask-Login==0.1.3
+ sudo pip install oauth2client
+ sudo pip install requests
+ sudo pip install httplib2
* Now setup by : python database_setup.py
* Now load menu items by : python lotsofmenus.py
* Now Start Local server By running : python project.py
* open in your browser :- https://localhost:9000
