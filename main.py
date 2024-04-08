import datetime
import os
from datetime import date

from flask import Flask, render_template, redirect, url_for, request, session
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from wtforms import StringField, SubmitField, IntegerField
from wtforms.validators import DataRequired

SCOPES = ["https://www.googleapis.com/auth/calendar"]

app = Flask(__name__)
Bootstrap5(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
calanderAPIKEY = "AIzaSyD0FwZgXFHpv1kOTr8e8tRek4zWF893SBc"
creds = None
app.secret_key = 'jbBrojb'
CLIENT_SECRETS_FILE = 'JBXamin/todoList/blob/master/credentials.json'
app.config.update({
    'OAUTH1_PROVIDER_ENFORCE_SSL': False
})

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_DATABASE_URI1'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class Task(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    task: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)


class Events(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    link: Mapped[str] = mapped_column(String(250), nullable=False)
    description: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)


class User(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    confirmPass: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()


class CreatePostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()], render_kw={"placeholder": "Title"})
    task = StringField("Task", validators=[DataRequired()], render_kw={"placeholder": "Task separated with ', '"})
    submit = SubmitField("Submit Task")


class Event(FlaskForm):
    title = StringField("Title", validators=[DataRequired()], render_kw={"placeholder": "Title"})
    description = StringField("Description", render_kw={"placeholder": "Description (if any)"})
    duration = IntegerField("Duration", validators=[DataRequired()], render_kw={"placeholder": "Length of the event"})
    count = IntegerField("Number of meetings", validators=[DataRequired()])
    attendees = StringField("Attendees", validators=[DataRequired()],
                            render_kw={"placeholder": "Email's of attendees separated with ', '"})
    submit = SubmitField("Submit Task")


@app.route("/")
def mainPage():
    return render_template("index.html")


@app.route("/register", methods=["POST", "GET"])
def start():
    if request.method == "POST":
        registeredUser = User(
            name=request.form.get('name'),
            password=request.form.get('pass'),
            confirmPass=request.form.get('confirmpass'),
        )
        db.session.add(registeredUser)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("start.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    global creds
    if request.method == "POST":
        usersDB = db.session.execute(db.select(User).order_by(User.id))
        Users = usersDB.scalars().all()
        for x in Users:
            if x.name == request.form.get('name') and x.password == request.form.get('pass'):
                return redirect(url_for("main", loginID=x.name))

        return redirect(url_for("login"))
    return render_template("login.html")


@app.route('/main/<string:loginID>', methods=["POST", "GET"])
def main(loginID):
    result = db.session.execute(db.select(Task).order_by(Task.id))
    all_tasks = result.scalars().all()
    result1 = db.session.execute(db.select(Events).order_by(Events.id))
    all_events = result1.scalars().all()
    return render_template("main.html", all_tasks=all_tasks, all_events=all_events)


@app.route('/newTask', methods=["POST", "GET"])
def newTask():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = Task(
            title=form.title.data,
            task=form.task.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("main"))
    return render_template('make-task.html', form=form)


@app.route('/authorize',methods=["POST", "GET"])
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True, _scheme='http')  # Use HTTP scheme
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    # Store the state so the callback can verify the auth server response.
    session['state'] = state
    return redirect(authorization_url)


@app.route('/oauth2callback', methods=["POST", "GET"])
def oauth2callback():
    # Specify the state when creating the flow in the callback.
    state = session.pop('state', None)
    if state is None:
        return 'Missing state parameter', 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True, _scheme='http')
    )

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('newEvent'))


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


@app.route('/newEvent', methods=["POST", "GET"])
def newEvent():
    form = Event()
    if form.validate_on_submit():
        attendeesL = form.attendees.data.split(", ")
        attendees = []
        for att in attendeesL:
            attendees += {'email': att}
        st = datetime.datetime.utcnow()

        end = datetime.datetime.utcnow() + datetime.timedelta(hours=int(form.duration.data))
        start_formatted = st.isoformat() + 'Z'
        end_formatted = end.isoformat() + 'Z'

        event = {
            'summary': form.title.data,
            'description': form.description.data,
            'start': {
                'dateTime': start_formatted,
                'timeZone': "Europe/London",
            },
            'end': {
                'dateTime': end_formatted,
                'timeZone': "Europe/London",
            },
            'recurrence': [
                f'RRULE:FREQ=DAILY;COUNT={form.count.data}'
            ],
            'attendees': attendees,
            'reminders': {
                'useDefault': False,
                'overrides': [
                    {'method': 'email', 'minutes': 24 * 60},
                    {'method': 'popup', 'minutes': 10},
                ],
            },
        }

        service = build('calendar', 'v3', credentials=creds)
        event = service.events().insert(calendarId="hajitu54@gmail.com", body=event).execute()
        new_event = Events(
            title=form.title.data,
            link=event.get('htmlLink'),
            description=form.description.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_event)
        db.session.commit()
        return redirect(url_for("main"))
    return render_template('make-event.html', form=form)


@app.route("/show/<int:ids>", methods=["POST", "GET"])
def showTask(ids):
    if request.method == "POST":
        requested_title = db.session.execute(db.select(Task).where(Task.id == ids)).scalar()
        taskList = requested_title.task.split(", ")
        removeList = request.form.getlist("checkbox")
        for rEmove in removeList:
            taskList.remove(rEmove)
        taskStr = ""
        for it in taskList:
            taskStr += it
            taskStr += ", "
        taskStr = taskStr[0:(len(taskStr) - 2)]
        requested_title.task = taskStr
        db.session.commit()
        return redirect(url_for("main"))
    requested_title = db.session.execute(db.select(Task).where(Task.id == ids)).scalar()
    taskList = requested_title.task.split(", ")
    return render_template("show-Task.html", task=requested_title, id=ids, tasks=taskList)


@app.route("/deleteTask/<int:task_Id>")
def delT(task_Id):
    deleteTask = db.session.execute(db.select(Task).where(Task.id == task_Id)).scalar()
    db.session.delete(deleteTask)
    db.session.commit()
    return redirect(url_for("main"))


@app.route("/deleteEvent/<int:task_Id>")
def delE(task_Id):
    deleteTask = db.session.execute(db.select(Events).where(Events.id == task_Id)).scalar()
    db.session.delete(deleteTask)
    db.session.commit()
    return redirect(url_for("main"))


if __name__ == "__main__":
    app.run(debug=True)
