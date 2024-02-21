from django.db import models
from users.models import User


class Post(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(null=True, blank=True)
    image = models.ImageField(default="media/default.jpg", upload_to="media")
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return str(self.title)


class Comment(models.Model):
    body = models.TextField(null=True, blank=True)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return str(self.body)


class SubComment(models.Model):
    body = models.TextField(null=True, blank=True)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return str(self.body)


class Like(models.Model):
    Bool = models.BooleanField(default=False)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return str(self.post.title)


class SubLike(models.Model):
    Bool = models.BooleanField(default=False)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return str(self.comment.body)
