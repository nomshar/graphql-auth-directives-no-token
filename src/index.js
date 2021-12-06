const { ForbiddenError, AuthenticationError } = require('apollo-server-errors');
const { IncomingMessage } = require("http");
const { SchemaDirectiveVisitor } = require("@graphql-tools/utils");
const {
  DirectiveLocation,
  GraphQLDirective,
  GraphQLList,
  GraphQLString
} = require("graphql");

const getUser = ({ context }) => {
  const req =
    context instanceof IncomingMessage
      ? context
      : context.req || context.request;

  if (!(req || req.headers)) {
    throw new AuthenticationError("No request object");
  }

  const user = JSON.parse(req.headers["x-user"])
  if (!user)
  {
    throw new AuthenticationError("No authorized user.");
  }

  return {
    hasRoles: (roles) => {
      const userRoles = process.env.AUTH_DIRECTIVES_ROLE_KEY
        ? user[process.env.AUTH_DIRECTIVES_ROLE_KEY] || []
        : user["groups"] ||
          user["Roles"] ||
          user["roles"] ||
          user["Role"] ||
          user["role"] ||
          [];
      
      return roles.some(role => userRoles.indexOf(role) !== -1);
    },
    hasScopes: (scopes) => {
      const userScopes = process.env.AUTH_DIRECTIVES_SCOPE_KEY
        ? user[process.env.AUTH_DIRECTIVES_SCOPE_KEY] || []
        : user["scp"] ||
          user["permissions"] ||
          user["Permissions"] ||
          user["Scopes"] ||
          user["scopes"] ||
          user["Scope"] ||
          user["scope"] ||
          [];

      return scopes.some(scope => userScopes.indexOf(scope) !== -1);
    }
  }

};

class SchemaVisitor extends SchemaDirectiveVisitor {
  static visitSchemaDirectives (schema, directives) {
    SchemaDirectiveVisitor.visitSchemaDirectives(schema, directives);
  }
}

class HasScopeDirective extends SchemaDirectiveVisitor {
  static getDirectiveDeclaration(directiveName, schema) {
    return new GraphQLDirective({
      name: "hasScope",
      locations: [DirectiveLocation.FIELD_DEFINITION, DirectiveLocation.OBJECT],
      args: {
        scopes: {
          type: new GraphQLList(GraphQLString),
          defaultValue: "none:read"
        }
      }
    });
  }

  // used for example, with Query and Mutation fields
  visitFieldDefinition(field) {
    const expectedScopes = this.args.scopes;
    const fieldName = field.name;
    const next = field.resolve;

    // wrap resolver with auth check
    field.resolve = function(result, args, context, info) {
      const user = context.user ?? getUser({ context });
      if (user.hasScopes(expectedScopes )) {
        return next ? next(result, args, { ...context, user }, info) : result[fieldName];
      }

      throw new ForbiddenError('You are not authorized for this resource', {field: fieldName });
    };
  }

  visitObject(obj) {
    const fields = obj.getFields();
    const expectedScopes = this.args.scopes;
    objName = obj.name;

    Object.keys(fields).forEach(fieldName => {
      const field = fields[fieldName];
      const next = field.resolve;
      field.resolve = function(result, args, context, info) {
        const user = context.user ?? getUser({ context });
        if (user.hasScopes(expectedScopes)) {
          return next ? next(result, args, { ...context, user }, info) : result[fieldName];
        }
        throw new ForbiddenError('You are not authorized for this resource', {type: objName });
      };
    });
  }
}

class HasRoleDirective extends SchemaDirectiveVisitor {
  static getDirectiveDeclaration(directiveName, schema) {
    return new GraphQLDirective({
      name: "hasRole",
      locations: [DirectiveLocation.FIELD_DEFINITION, DirectiveLocation.OBJECT],
      args: {
        roles: {
          type: new GraphQLList(GraphQLString)
        }
      }
    });
  }

  visitFieldDefinition(field) {
    const expectedRoles = this.args.roles;
    const fieldName = field.name;
    const next = field.resolve;

    field.resolve = function(result, args, context, info) {
      const user = context.user ?? getUser({ context });
      if (user.hasRoles(expectedRoles)) {
        return next ? next(result, args, { ...context, user }, info) : result[fieldName];
      }

      throw new ForbiddenError('You are not authorized for this resource', {field: fieldName });
    };
  }

  visitObject(obj) {
    const fields = obj.getFields();
    const expectedRoles = this.args.roles;
    const objName = obj.name;
    const directiveName = this.name;

    Object.keys(fields).forEach(fieldName => {
      const field = fields[fieldName];
      const next = field.resolve;
      
      field.resolve = function(result, args, context, info) {
        if (context.visitedDirective !== undefined && context.visitedDirective[directiveName][objName])
        {
          return next ? next(result, args, { ...context, user }, info) : result[fieldName];
        }
        
        context.visitedDirective = { [directiveName]: {[objName]: true} };
        
        
        const user = context.user ?? getUser({ context });
        if (user.hasRoles(expectedRoles)) {
          return next ? next(result, args, { ...context, user }, info) : result[fieldName];
        }
        throw new ForbiddenError('You are not authorized for this resource', {type: objName });
      };
    });
  }
}

class IsAuthenticatedDirective extends SchemaDirectiveVisitor {
  static getDirectiveDeclaration(directiveName, schema) {
    return new GraphQLDirective({
      name: "isAuthenticated",
      locations: [DirectiveLocation.FIELD_DEFINITION, DirectiveLocation.OBJECT]
    });
  }

  visitObject(obj) {
    const fields = obj.getFields();

    Object.keys(fields).forEach(fieldName => {
      const field = fields[fieldName];
      const next = field.resolve;

      field.resolve = function(result, args, context, info) {
        const user = getUser({ context }); // will throw error if not valid signed jwt
        return next(result, args, { ...context, user }, info);
      };
    });
  }

  visitFieldDefinition(field) {
    const next = field.resolve;

    field.resolve = function(result, args, context, info) {
      const user = getUser({ context });
      return next(result, args, { ...context, user }, info);
    };
  }
}

module.exports = { HasRoleDirective, HasScopeDirective, IsAuthenticatedDirective, SchemaVisitor };