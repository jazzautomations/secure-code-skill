app.get("/order/:id", requireAuth, (req,res) => db.order.findFirst({ where:{ id:req.params.id, userId:req.session.userId }}));
