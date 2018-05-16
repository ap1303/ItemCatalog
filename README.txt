For running the app, run 'python database_setup.py' first to initialize the database, and run 'python project.py' to initiate the server process.
After initiating the server process, open the browser and visit localhost:5000/catalog/homepage. By now, the application should be up and running!

The app uses Google's oauth API to authenticate each user and establish an entry for each user in login_session, indexed by their respective access token.

If for each user, current operation, be it Create, Read, Update, or Delete, takes place 30 min or more after the last operation, then the server deems the user not
valid, and asks the user to re-login. note that as stipulated by the Google API, the access token expires after 1h. But since after initial login of each user, the
web app will have basically 0 business to do with Google's backend server, so I decided not to refresh the access token even after it expires.

After 1h, the server actively (that is, independent of any client activity) cleans its session data, that is, removing any duplicates, which might arise since
when each user initially uses the web app each time, no identification information can be obtained from the user by the server, hence we don't know whether the user has logged in
or not



