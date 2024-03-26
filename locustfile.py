from locust import HttpUser, task, between


class UserApi(HttpUser):
    wait_time = between(0.5, 2.5)

    @task
    def get_user(self):
        self.client.get("/users/reset-password")

