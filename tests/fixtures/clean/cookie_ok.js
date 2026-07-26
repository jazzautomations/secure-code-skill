res.cookie("session", jwt, { httpOnly: true, secure: true, sameSite: "lax" });
