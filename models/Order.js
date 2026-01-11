const mongoose = require("mongoose");

const OrderSchema = new mongoose.Schema({
  foodName: String,
  quantity: Number,
  totalPrice: Number,
  status: {
    type: String,
    default: "Ordered"
  }
});

module.exports = mongoose.model("Order", OrderSchema);
