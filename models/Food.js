const mongoose = require("mongoose");

const FoodSchema = new mongoose.Schema({
  name: String,
  price: Number,
  category: String,
  available: Boolean
});

module.exports = mongoose.model("Food", FoodSchema);
