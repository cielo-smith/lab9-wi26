import os
import time
import uuid
from contextlib import asynccontextmanager

import bcrypt
import mysql.connector
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from dotenv import load_dotenv

load_dotenv()

class PostCreate(BaseModel):
    title: str
    body: str


def get_db():
    conn = mysql.connector.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
    )
    try:
        yield conn
    finally:
        conn.close()


def get_current_user(
    session_token: str | None = Cookie(None),
    conn=Depends(get_db),
):
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT users.id, users.username FROM sessions "
        "JOIN users ON sessions.user_id = users.id "
        "WHERE sessions.session_token = %s",
        (session_token,),
    )
    user = cursor.fetchone()
    cursor.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return user


@asynccontextmanager
async def lifespan(app: FastAPI):
    for _ in range(30):
        try:
            conn = mysql.connector.connect(
                host=os.environ["DB_HOST"],
                user=os.environ["DB_USER"],
                password=os.environ["DB_PASSWORD"],
                database=os.environ["DB_NAME"],
            )
            cursor = conn.cursor()
            with open("init.sql") as f:
                for statement in f.read().split(";"):
                    statement = statement.strip()
                    if statement:
                        cursor.execute(statement)
            conn.commit()
            cursor.close()
            conn.close()
            break
        except mysql.connector.Error:
            time.sleep(1)
    yield


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request, session_token: str | None = Cookie(None), conn=Depends(get_db)):
    if session_token:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT users.id FROM sessions "
            "JOIN users ON sessions.user_id = users.id "
            "WHERE sessions.session_token = %s",
            (session_token,),
        )
        user = cursor.fetchone()
        cursor.close()
        if user:
            return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("home.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, conn=Depends(get_db), current_user=Depends(get_current_user)):
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": current_user["username"]})


@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), conn=Depends(get_db)):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, hashed.decode()),
        )
        conn.commit()
    except mysql.connector.IntegrityError:
        cursor.close()
        raise HTTPException(status_code=409, detail="Username already exists")
    user_id = cursor.lastrowid
    session_token = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, session_token),
    )
    conn.commit()
    cursor.close()
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="session_token", value=session_token, httponly=True, secure=True)
    return response

# TODO: Add POST /login endpoint
#       - Accept username and password from the form (use Form(...) from fastapi)
#       - Look up the user by username, verify password with bcrypt.checkpw
#       - Create a session: generate a uuid4 token, insert into sessions table
#       - Set the session_token as an httponly cookie using response.set_cookie()
#       - Redirect to "/posts" on success, return 401 on failure
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), conn=Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))

    user = cursor.fetchone()

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        cursor.close()

    session_token = str(uuid.uuid4())

    cursor.execute(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user["id"], session_token),
    )

    conn.commit()
    cursor.close()

    response = RedirectResponse(url="/posts", status_code=303)
    response.set_cookie(key="session_token", value=session_token, httponly=True, secure=True)
    return response



@app.post("/logout")
def logout(session_token: str | None = Cookie(None), conn=Depends(get_db)):
    if session_token:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_token = %s", (session_token,))
        conn.commit()
        cursor.close()
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session_token")
    return response

# TODO: Add GET /me endpoint that returns the current user's info using get_current_user dependency
@app.get("/me")
def get_me(current_user=Depends(get_current_user)):
    return current_user

# TODO: Add PUT /me/password endpoint that lets the current user change their password
@app.put("/me/password")
def change_password(new_password: str = Form(...), conn=Depends(get_db), current_user=Depends(get_current_user)):
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())

    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed.decode(), current_user["id"]))

    conn.commit()
    cursor.close()

    return {"detail": "password updated"}


@app.post("/posts")
def create_post(post: PostCreate, conn=Depends(get_db), current_user=Depends(get_current_user)):
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO posts (user_id, title, body) VALUES (%s, %s, %s)",
        (current_user["id"], post.title, post.body),
    )
    conn.commit()
    post_id = cursor.lastrowid
    cursor.close()
    return {"id": post_id, "user_id": current_user["id"], "title": post.title, "body": post.body}


@app.get("/posts")
def list_posts(conn=Depends(get_db)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts")
    posts = cursor.fetchall()
    cursor.close()
    return posts


@app.get("/posts/{post_id}")
def get_post(post_id: int, conn=Depends(get_db)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    cursor.close()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


@app.put("/posts/{post_id}")
def update_post(post_id: int, post: PostCreate, conn=Depends(get_db), current_user=Depends(get_current_user)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    existing = cursor.fetchone()
    if not existing:
        cursor.close()
        raise HTTPException(status_code=404, detail="Post not found")
    if existing["user_id"] != current_user["id"]:
        cursor.close()
        raise HTTPException(status_code=403, detail="Not your post")
    cursor.execute(
        "UPDATE posts SET title = %s, body = %s WHERE id = %s",
        (post.title, post.body, post_id),
    )
    conn.commit()
    cursor.close()
    return {"id": post_id, "user_id": current_user["id"], "title": post.title, "body": post.body}


@app.delete("/posts/{post_id}")
def delete_post(post_id: int, conn=Depends(get_db), current_user=Depends(get_current_user)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    existing = cursor.fetchone()
    if not existing:
        cursor.close()
        raise HTTPException(status_code=404, detail="Post not found")
    if existing["user_id"] != current_user["id"]:
        cursor.close()
        raise HTTPException(status_code=403, detail="Not your post")
    cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    conn.commit()
    cursor.close()
    return {"detail": "Post deleted"}
