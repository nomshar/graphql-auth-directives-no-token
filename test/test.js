const test = require("ava");

const { ApolloClient } = require("apollo-client");
const { createHttpLink } = require("apollo-link-http");
const { InMemoryCache } = require("apollo-cache-inmemory");

const gql = require("graphql-tag");
const fetch = require("node-fetch");

let client;

const headers = {
  "x-error": "Middleware error"
};

test.before(() => {
  client = new ApolloClient({
    link: createHttpLink({ uri: "http://localhost:3000", fetch, headers }),
    cache: new InMemoryCache()
  });
});

test("Fail if no auth token", async t => {
  t.plan(1);

  const client = new ApolloClient({
    link: createHttpLink({ uri: "http://localhost:3000", fetch }),
    cache: new InMemoryCache()
  });

  await client
    .query({
      query: gql`
        {
          userById(userId: "123456") {
            id
            name
          }
        }
      `
    })
    .then(data => {
      t.fail("AuthorizationError should be thrown");
    })
    .catch(error => {
      t.pass();
    });
});

test("No error with token", async t => {
  t.plan(1);

  const headers = {
    "x-user": {
      roles: ["admin", "user"],
      scopes: ["User:Read", "Item:Read", "User:Create", "Item:Create"]
    }
  };

  const client = new ApolloClient({
    link: createHttpLink({ uri: "http://localhost:3000", fetch, headers }),
    cache: new InMemoryCache()
  });

  await client
    .query({
      query: gql`
        {
          userById(userId: "123456") {
            id
            name
          }
        }
      `
    })
    .then(data => {
      // TODO: verify expected data
      t.pass();
    })
    .catch(error => {
      console.error(error);
      t.fail();
    });
});

test("Mutation resolver is not called when Auth fails", async t => {
  t.plan(1);

  // This JWT does not contain User:Create scope claim
  const headers = {
    "x-user": {
      roles: ["admin", "user"],
      scopes: ["User:Read", "Item:Read", "Item:Create"]
    }
  };

  const client = new ApolloClient({
    link: createHttpLink({ uri: "http://localhost:3000", fetch, headers }),
    cache: new InMemoryCache()
  });

  await client
    .mutate({
      mutation: gql`
        mutation {
          createUser(id: "1234", name: "Bob") {
            id
          }
        }
      `
    })
    .then(data => {
      t.fail("User should not be authorized for this mutation");
    })
    .catch(error => {
      //console.log(error.message);
      t.pass();
    });
});
