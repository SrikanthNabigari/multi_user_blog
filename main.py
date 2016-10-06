import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2
import time
from google.appengine.ext import ndb
from datastore import *
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 's#e%c^r(e)t'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        ''' reads the user id from cookie which stored in browser '''
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    
    # sets the cookie when user logged in
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))
    # empty's the cookie when user logged out
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return ndb.Key('users', group)

##### blog stuff

def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

def comments_key(name = 'default'):
    return ndb.Key('comments', name)


class BlogFront(BlogHandler):
        
    def get(self):
        uid = self.read_secure_cookie('user_id')
        liked = Like.query()
        comments = Comment.query()  
        posts = greetings = Post.query().order(-Post.created)
        if uid:
            key = ndb.Key('User', int(uid), parent=users_key())
            curr_user = key.get()
            self.render('front.html', posts=posts, user = curr_user, liked=liked,comments=comments)
        else:
            self.render('front.html', posts=posts, liked=liked,comments=comments)       
    def post(self):
        uid = self.read_secure_cookie('user_id')
        self.post_id = self.request.get('post_id')
        self.like = self.request.get('like')
        self.unlike = self.request.get('unlike')
        self.comment = self.request.get('comment')
        self.comment_id = self.request.get('comment_id')
        self.comment_edit = self.request.get('comment_edit')
        self.comment_delete = self.request.get('comment_delete')
        self.delete_comment_id = self.request.get('delete_comment_id')
        key = ndb.Key('Post', int(self.post_id), parent=blog_key())
        post = key.get()
        if uid:
            key = ndb.Key('User', int(uid), parent=users_key())
            curr_user = key.get()
        if self.like:
            # when user likes  the post
            if self.user:
                post.likes += 1
                like = Like(post_id=int(self.post_id), author=curr_user)
                like.put()
                post.put()
                time.sleep(0.2)
            self.redirect("/blog/")
        elif self.unlike:
            # when user unlikes the post
            if self.user:
                post.likes -= 1
                like = Like.gql("WHERE post_id = :1 AND author.name = :2",
                                int(self.post_id), curr_user.name).get()
                key = like.key
                key.delete()
                post.put()
                time.sleep(0.2)
            self.redirect("/blog")
        if self.comment:
            # when user comments in the post           
            if post and self.user:
                comment = Comment(parent = comments_key(),
                                  content = self.comment,
                                  post_id=int(self.post_id), author=curr_user)
                comment.put()
                time.sleep(0.2)
            self.redirect("/blog")  
        if self.comment_edit:
            # edits the comment of a post
            key = ndb.Key('Comment', int(self.comment_id), parent=comments_key())
            comment_key = key.get()
            if comment_key and self.user:
                comment_key.content = self.comment_edit
                comment_key.put()
                time.sleep(0.2)
            self.redirect("/blog")
        if self.comment_delete:
            # deletes the comment of a post
            key = ndb.Key('Comment', int(self.delete_comment_id), parent=comments_key())
            comment_key = key.get()
            if comment_key and self.user:
                key.delete()
                time.sleep(0.2)
            self.redirect("/blog")         
                
        
class PostPage(BlogHandler):
    ''' when new post is posted '''
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    ''' renders the new post page '''
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        uid = self.read_secure_cookie('user_id')
        #key = db.Key('User', int(uid), parent=users_key())
        curr_user = User.by_id(int(uid))

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = curr_user)
            p.put()
            self.redirect('/blog/%s' % str(p.key.id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)
class EditPost(BlogHandler):
    ''' renders the post editing page '''
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return
        self.render("editpost.html", post = post)
    def post(self, post_id):
        # edits the post   
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        uid = self.read_secure_cookie('user_id')
        key = ndb.Key('User', int(uid), parent=users_key())
        curr_user = key.get()
        self.subject = self.request.get('subject')
        self.content = self.request.get('content')
        if self.subject and self.content:
            if curr_user.name == post.author.name:
                post.subject = self.subject
                post.content = self.content
                post.put()                
                self.redirect('/blog/')
            else:
                self.error(404)
                return     
class DeletePost(BlogHandler):
    ''' renders the delete confirmation of a post page'''
    def get(self, post_id):
        uid = self.read_secure_cookie('user_id')
        key = ndb.Key('User', int(uid), parent=users_key())
        curr_user = key.get()
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if post.author.name == curr_user.name:
            self.render("deletepost.html", post=post)
        else:
            self.error(404)
            return
    def post(self, post_id):
        # deletes the post
        uid = self.read_secure_cookie('user_id')
        key = ndb.Key('User', int(uid), parent=users_key())
        curr_user = key.get()
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if self.request.get('delete'):
            if post.author.name == curr_user.name:
                key.delete()
                self.redirect("/blog/")
            else:
                self.error(404)
                return    

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    ''' renders the Signup form page '''
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    ''' registers the user credentials '''
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    ''' renders the login page '''
    def get(self):
        if self.user:
            self.redirect('/blog')
        else:    
            self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    ''' Logs out the user '''
    def get(self):
        self.logout()
        self.redirect('/login')

# Unit 2 HW
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
