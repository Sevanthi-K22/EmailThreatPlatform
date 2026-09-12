function login() {

    const username =
        document.getElementById("username").value.trim();

    const password =
        document.getElementById("password").value;

    const message =
        document.getElementById("loginMessage");


    if (
        username === "admin" &&
        password === "admin123"
    ) {

        sessionStorage.setItem("investigator_session", "active");

        message.textContent =
            "Login successful! Entering investigation center...";

        message.style.color = "#168b51";


        setTimeout(() => {

            window.location.href =
                "dashboard.html";

        }, 400);

    } else {

        message.textContent =
            "Invalid username or password (use admin / admin123)";

        message.style.color = "#d52f2f";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById("password");
    const usernameInput = document.getElementById("username");

    if (passwordInput) {
        passwordInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                login();
            }
        });
    }

    if (usernameInput) {
        usernameInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                login();
            }
        });
    }
});