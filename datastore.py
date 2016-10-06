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


# user stuff
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
def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

def comments_key(name = 'default'):
    return ndb.Key('comments', name)
class User(ndb.Model):
    ''' Users data table '''
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.gql("WHERE name = '%s'" % name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
class Post(ndb.Model):
    ''' Post data table '''
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    author = ndb.StructuredProperty(User)
    likes = ndb.IntegerProperty(default = 0)

class Like(ndb.Model):
    ''' likes data table of a post '''
    post_id = ndb.IntegerProperty(required=True)
    author = ndb.StructuredProperty(User)

class Comment(ndb.Model):
    ''' comments data table of a post '''
    content = ndb.StringProperty(required=True)
    post_id = ndb.IntegerProperty(required=True)
    author = ndb.StructuredProperty(User)        