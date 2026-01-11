const express = require("express");
const Order = require("../models/Order");
const Food = require("../models/Food");

const router = express.Router();

router.post("/place", async (req, res) => {
  const { foodId, quantity } = req.body;

  const food = await Food.findById(foodId);
  const totalPrice = food.price * quantity;

  await Order.create({
    foodName: food.name,
    quantity,
    totalPrice
  });

  res.json({ totalPrice });
});

router.get("/view", async (req, res) => {
  const orders = await Order.find();
  res.json(orders);
});

module.exports = router;
