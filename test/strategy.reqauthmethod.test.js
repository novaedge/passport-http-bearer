var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {

  describe("with options.reqAuthMethod === 'header'", function() {
    var strategy = new Strategy({ passReqToCallback: true, reqAuthMethod: 'header' }, function(req, token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' }, { scope: 'read', foo: req.headers['x-foo'] });
      }
      return done(null, false);
    });

    describe('handling a request with valid header token', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer vF9dft4qmT';
            req.headers['x-foo'] = 'hello';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });

      it('should supply request header in info', function() {
        expect(info.foo).to.equal('hello');
      });
    });

    describe('handling a request with valid header and invalid body parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer vF9dft4qmT';
            req.headers['x-foo'] = 'hello';
            req.body = {};
            req.body.access_token = 'invalid_token';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with valid header and invalid query parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer vF9dft4qmT';
            req.headers['x-foo'] = 'hello';
            req.query = {};
            req.query.access_token = 'invalid_token';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with wrong token in header', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer WRONG';
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users", error="invalid_token"');
      });
    });

    describe('handling a request without credentials', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users"');
      });
    });
  });

  describe("with options.reqAuthMethod === 'body'", function() {
    var strategy = new Strategy({ passReqToCallback: true, reqAuthMethod: 'body' }, function(req, token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' }, { scope: 'read', foo: req.headers['x-foo'] });
      }
      return done(null, false);
    });

    describe('handling a request with valid token in body parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.body = {};
            req.body.access_token = 'vF9dft4qmT';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with valid body and invalid header parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer invalid_token';
            req.headers['x-foo'] = 'hello';
            req.body = {};
            req.body.access_token = 'vF9dft4qmT';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with valid body and invalid query parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.body = {};
            req.body.access_token = 'vF9dft4qmT';
            req.query = {};
            req.query.access_token = 'invalid_token';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with wrong token in body', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.body = {};
            req.body.access_token = 'invalid_token';
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users", error="invalid_token"');
      });
    });

    describe('handling a request without credentials', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users"');
      });
    });
  });

  describe("with options.reqAuthMethod === 'query'", function() {
    var strategy = new Strategy({ passReqToCallback: true, reqAuthMethod: 'query' }, function(req, token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' }, { scope: 'read', foo: req.headers['x-foo'] });
      }
      return done(null, false);
    });

    describe('handling a request with valid token in query parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.query = {};
            req.query.access_token = 'vF9dft4qmT';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with valid query and invalid header parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer invalid_token';
            req.headers['x-foo'] = 'hello';
            req.query = {};
            req.query.access_token = 'vF9dft4qmT';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with valid query and invalid body parameter', function() {
      var user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.body = {};
            req.body.access_token = 'invalid_token';
            req.query = {};
            req.query.access_token = 'vF9dft4qmT';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });
    });

    describe('handling a request with wrong token in query', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.query = {};
            req.query.access_token = 'invalid_token';
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users", error="invalid_token"');
      });
    });

    describe('handling a request without credentials', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users"');
      });
    });
  });

  describe("with options.reqAuthMethod === 'wrong'", function() {
    var strategy = new Strategy({ passReqToCallback: true, reqAuthMethod: 'wrong' }, function(req, token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' }, { scope: 'read', foo: req.headers['x-foo'] });
      }
      return done(null, false);
    });

    describe('handling a request valid header parameter', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer vF9dft4qmT';
            req.headers['x-foo'] = 'hello';
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users"');
      });
    });

    describe('handling a request valid body parameter', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.body = {};
            req.body.access_token = 'vF9dft4qmT';
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users"');
      });
    });

    describe('handling a request valid query parameter', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.query = {};
            req.query.access_token = 'vF9dft4qmT';
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users"');
      });
    });

    describe('handling a request without credentials', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users"');
      });
    });
  });

});
