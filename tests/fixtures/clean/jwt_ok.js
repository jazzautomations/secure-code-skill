const claims = jwt.verify(tokenStr, secret, { algorithms: ["HS256"] });
