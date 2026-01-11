const express = require("express");
const mongoose = require("mongoose");
const Food = require("../models/Food");

const router = express.Router();

/* =====================
   ADD FOOD (ADMIN)
===================== */
router.post("/add", async (req, res) => {
  try {
    const { name, price, category, available } = req.body;

    await Food.create({
      name,
      price,
      category,
      available
    });

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.json({ success: false, message: "Error adding food" });
  }
});

/* =====================
   VIEW FOOD (ALL)
===================== */
router.get("/view", async (req, res) => {
  const foods = await Food.find({});
  res.json(foods);
});

/* =====================
   UPDATE FOOD (ADMIN) — FIXED
===================== */
router.post("/update", async (req, res) => {
  try {
    const { id, name, price, category } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.json({ success: false, message: "Invalid ID" });
    }

    const result = await Food.updateOne(
      { _id: new mongoose.Types.ObjectId(id) },
      {
        $set: {
          name,
          price,
          category
        }
      }
    );

    if (result.modifiedCount === 0) {
      return res.json({
        success: false,
        message: "No document updated"
      });
    }

    return res.json({ success: true });

  } catch (err) {
    console.error(err);
    return res.json({ success: false, message: "Update failed" });
  }
});

/* =====================
   DELETE FOOD (ADMIN)
===================== */
router.post("/delete", async (req, res) => {
  try {
    await Food.deleteOne({ _id: req.body.id });
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.json({ success: false });
  }
});

module.exports = router;
