For running the app, run 'python database_setup.py' first to initialize the database, and run 'python project.py' to initiate the server process.
After initiating the server process, open the browser and visit port 5000 of localhost. By now, the application should be up and running!

After logging in, every time the user wants to perform an action that requires user registration, the server first checks if the access token provided in 
the url of the request is the correct token, that is, the token that's stored in login_session['access_token']; if not, the server will ask the user to log
in again. If it is the correct token, a request for refreshing the access token will be sent to the Google server with the refresh token in order to prevent
session timeout. If the request succeeds, the app continues running; if the request didn't succeed, prompt the user for re-login
