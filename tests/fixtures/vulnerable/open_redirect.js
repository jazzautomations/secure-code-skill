app.get("/go", (req,res) => res.redirect(req.query.next));
