const request = require('supertest');
const chai = require("chai");
const app = require("./app");

const expect = chai.expect;


describe("AuthMiddleware and App Routes", () => {
  let registeredEmail = "test@example.com";
  let registeredPassword = "password123";

  it("should register a new user", (done) => {
    request(app)
      .post("/register")
      .send({ email: registeredEmail, password: registeredPassword })
      .expect(200)
      .end((err, res) => {
        expect(res.text).to.equal("User registered successfully!");
        done(err);
      });
  });

  it("should login the user", (done) => {
    request(app)
      .post("/login")
      .send({ email: registeredEmail, password: registeredPassword })
      .expect(200)
      .end((err, res) => {
        expect(res.headers["set-cookie"]).to.exist; // Check if the cookie is set
        done(err);
      });
  }); 

  it("should logout the user", (done) => {
    const agent = request.agent(app);

    agent
      .post("/login")
      .send({ email: registeredEmail, password: registeredPassword })
      .end((err, res) => {
        agent
          .post("/logout")
          .expect(200)
          .end((err, res) => {
            expect(res.text).to.equal("Logged out successfully.");
            done(err);
          });
      });
  });

  it("should deny access to the protected route after logout", (done) => {
    request(app)
      .get("/protected")
      .expect(403)
      .end((err, res) => {
        expect(res.text).to.include('"user":null');
        done(err);
      });
  });
});