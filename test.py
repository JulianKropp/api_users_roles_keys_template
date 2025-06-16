from mongoengine import (
    Document, StringField, ListField,
    ReferenceField, connect, CASCADE, PULL, disconnect
)
import unittest


# Connect to test DB
connect(
    db="teeest",
    host="localhost",
    port=27017,
    username="admin",
    password="admin",
    authentication_source="admin"
)


# Models
class Author(Document):
    name = StringField(required=True)
    posts = ListField(ReferenceField('Post'))


class Post(Document):
    title = StringField(required=True)
    content = StringField()
    author = ReferenceField(Author, reverse_delete_rule=CASCADE)


# Register reverse delete rule
Post.register_delete_rule(Author, 'posts', PULL)


class AuthorPostRelationshipTest(unittest.TestCase):
    def setUp(self):
        # Clean up before each test
        Author.drop_collection()
        Post.drop_collection()

    def test_deleting_post_removes_from_author(self):
        author = Author(name="Alice").save()
        post1 = Post(title="Post 1", content="Content", author=author).save()
        post2 = Post(title="Post 2", content="Content", author=author).save()

        author.posts = [post1, post2]
        author.save()

        # Delete one post
        post1.delete()

        # Reload author
        author.reload()
        self.assertEqual(len(author.posts), 1)
        self.assertEqual(author.posts[0].id, post2.id)

    def test_deleting_author_deletes_all_posts(self):
        author = Author(name="Bob").save()
        post1 = Post(title="P1", content="...", author=author).save()
        post2 = Post(title="P2", content="...", author=author).save()

        author.posts = [post1, post2]
        author.save()

        # Delete author
        author.delete()

        # Check posts deleted
        self.assertEqual(Post.objects.count(), 0)

    def tearDown(self):
        # Clean up after each test
        Author.drop_collection()
        Post.drop_collection()


if __name__ == '__main__':
    unittest.main()
