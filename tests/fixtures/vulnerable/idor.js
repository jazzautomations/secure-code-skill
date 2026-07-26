app.get("/order/:id", (req,res) => db.order.findUnique({ where:{ id:req.params.id }}));
