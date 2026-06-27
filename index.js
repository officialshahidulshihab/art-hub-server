const express = require("express");
const cors = require("cors");

const dotenv = require("dotenv");
dotenv.config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");
const app = express();
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 5000;

const uri = process.env.MONGODB_URI;

app.use(
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  }),
);
app.use(express.json());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`),
);

const verifyToken = async (req, res, next) => {
  const header = req?.headers.authorization;
  if (!header) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const token = header;

  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.decoded = payload;
    return next();
  } catch (error) {
    return res.status(403).json({ message: "Forbidden" });
  }
};

const verifyArtist = (req, res, next) => {
  if (req.decoded?.role !== "artist") {
    return res.status(403).json({ message: "Forbidden, artist only" });
  }
  next();
};

const verifyAdmin = (req, res, next) => {
  if (req.decoded?.role !== "admin") {
    return res.status(403).json({ message: "Forbidden, admin only" });
  }
  next();
};

async function run() {
  try {
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );

    const db = client.db(process.env.AUTH_DB_NAME);
    const artworkCollection = db.collection("artworks");
    const bannerCollection = db.collection("banners");
    const artistCollection = db.collection("artists");
    const purchaseCollection = db.collection("purchases");
    const subscriptionCollection = db.collection("subscriptions");
    const userCollection = db.collection("user");

    app.get("/api/artists/top", async (req, res) => {
      const artists = await artistCollection
        .find()
        .sort({ worksSold: -1 })
        .limit(3)
        .toArray();
      res.send(artists);
    });

    app.get("/api/artists", async (req, res) => {
      const artists = await artistCollection.find().toArray();
      res.send(artists);
    });

    app.get("/api/artists/:id", async (req, res) => {
      const { id } = req.params;
      const artist = await artistCollection.findOne({ _id: new ObjectId(id) });
      if (!artist) return res.status(404).json({ message: "Artist not found" });
      res.send(artist);
    });

    app.get("/api/artists/:id/artworks", async (req, res) => {
      const { id } = req.params;
      const result = await artworkCollection
        .find({ artistId: id })
        .sort({ createdAt: -1 })
        .toArray();
      res.send(result);
    });

    app.get("/api/artworks/featured", async (req, res) => {
      const artworks = await artworkCollection
        .find({ status: "published" })
        .sort({ createdAt: -1 })
        .limit(6)
        .toArray();
      res.send(artworks);
    });

    const commentCollection = db.collection("comments");

    
    app.get("/api/artworks/:id/comments", async (req, res) => {
      const { id } = req.params;
      const comments = await commentCollection
        .find({ artworkId: id })
        .sort({ createdAt: -1 })
        .toArray();

      const userIds = [...new Set(comments.map((c) => c.userId))];
      const users = await userCollection
        .find({
          _id: {
            $in: userIds
              .map((uid) => {
                try {
                  return new ObjectId(uid);
                } catch {
                  return null;
                }
              })
              .filter(Boolean),
          },
        })
        .toArray();

      const userMap = {};
      users.forEach((u) => {
        userMap[u._id.toString()] = u.name ?? u.email ?? "Collector";
      });

      const formatted = comments.map((c) => ({
        id: c._id.toString(),
        artworkId: c.artworkId,
        userId: c.userId,
        userName: userMap[c.userId] ?? "Collector",
        comment: c.comment,
        createdAt: c.createdAt,
      }));

      res.send(formatted);
    });

    app.post("/api/artworks/:id/comments", verifyToken, async (req, res) => {
      const { id } = req.params;
      const userId = req.decoded.id || req.decoded.sub;
      const role = req.decoded.role;

      if (role === "artist" || role === "admin") {
        return res
          .status(403)
          .json({ message: "Only collectors can comment." });
      }

      const hasPurchased = await purchaseCollection.findOne({
        userId,
        artworkId: id,
      });
      if (!hasPurchased) {
        return res
          .status(403)
          .json({ message: "You must own this artwork to comment." });
      }

      const { comment } = req.body;
      if (!comment || comment.trim().length === 0) {
        return res.status(400).json({ message: "Comment cannot be empty." });
      }

      const result = await commentCollection.insertOne({
        artworkId: id,
        userId,
        comment: comment.trim(),
        createdAt: new Date(),
      });

      res.send({ success: true, insertedId: result.insertedId });
    });

    app.patch("/api/comments/:commentId", verifyToken, async (req, res) => {
      const { commentId } = req.params;
      const userId = req.decoded.id || req.decoded.sub;
      const { comment } = req.body;

      if (!comment || comment.trim().length === 0) {
        return res.status(400).json({ message: "Comment cannot be empty." });
      }

      const existing = await commentCollection.findOne({
        _id: new ObjectId(commentId),
      });
      if (!existing)
        return res.status(404).json({ message: "Comment not found." });
      if (existing.userId !== userId)
        return res.status(403).json({ message: "Not your comment." });

      await commentCollection.updateOne(
        { _id: new ObjectId(commentId) },
        { $set: { comment: comment.trim(), updatedAt: new Date() } },
      );

      res.send({ success: true });
    });

    app.delete("/api/comments/:commentId", verifyToken, async (req, res) => {
      const { commentId } = req.params;
      const userId = req.decoded.id || req.decoded.sub;

      const existing = await commentCollection.findOne({
        _id: new ObjectId(commentId),
      });
      if (!existing)
        return res.status(404).json({ message: "Comment not found." });
      if (existing.userId !== userId)
        return res.status(403).json({ message: "Not your comment." });

      await commentCollection.deleteOne({ _id: new ObjectId(commentId) });
      res.send({ success: true });
    });

    app.get("/api/banners", async (req, res) => {
      const banners = await bannerCollection.find().toArray();
      res.send(banners);
    });

    app.get("/api/artworks/categories", async (req, res) => {
      const categories = await artworkCollection.distinct("category");
      res.send(categories);
    });

    app.get(
      "/api/artworks/mine",
      verifyToken,
      verifyArtist,
      async (req, res) => {
        const artistId = req.decoded.id || req.decoded.sub;
        const result = await artworkCollection
          .find({ artistId })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      },
    );

    app.get("/api/artworks", async (req, res) => {
      const { category } = req.query;
      const query = { status: "published" };
      if (category) {
        query.category = category;
      }
      const result = await artworkCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/api/artworks", verifyToken, verifyArtist, async (req, res) => {
      const artworkData = req.body;
      const artistId = req.decoded.id || req.decoded.sub;

      const result = await artworkCollection.insertOne({
        ...artworkData,
        artistId,
        status: "published",
        createdAt: new Date(),
      });
      res.send(result);
    });

    app.get("/api/artworks/:id", async (req, res) => {
      const { id } = req.params;
      const result = await artworkCollection.findOne({ _id: new ObjectId(id) });
      if (!result)
        return res.status(404).json({ message: "Artwork not found" });
      res.send(result);
    });

    app.patch(
      "/api/artworks/:id",
      verifyToken,
      verifyArtist,
      async (req, res) => {
        const { id } = req.params;
        const updatedData = req.body;
        const result = await artworkCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData },
        );
        res.send(result);
      },
    );

    app.patch(
      "/api/artist/profile",
      verifyToken,
      verifyArtist,
      async (req, res) => {
        const artistId = req.decoded.id || req.decoded.sub;
        const { location, statement, avatar } = req.body;

        const updateFields = { updatedAt: new Date() };
        if (location !== undefined && location !== "")
          updateFields.location = location;
        if (statement !== undefined && statement !== "")
          updateFields.bio = statement;
        if (avatar !== undefined && avatar !== "") updateFields.avatar = avatar;

        const byUserId = await artistCollection.updateOne(
          { userId: artistId },
          { $set: updateFields },
        );

        if (byUserId.matchedCount === 0) {
          try {
            await artistCollection.updateOne(
              { _id: new ObjectId(artistId) },
              { $set: updateFields },
            );
          } catch {}
        }

        res.send({ success: true });
      },
    );

    app.delete(
      "/api/artworks/:id",
      verifyToken,
      verifyArtist,
      async (req, res) => {
        const { id } = req.params;
        const result = await artworkCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      },
    );

    app.get("/api/collector/stats", verifyToken, async (req, res) => {
      const userId = req.decoded.id || req.decoded.sub;

      const purchases = await purchaseCollection.find({ userId }).toArray();
      const subscription = await subscriptionCollection.findOne({ userId });
      const planId = subscription?.planId || "collector";

      const planMaxMap = { collector: 3, pro: 9, premium: 9999 };
      const planNameMap = {
        collector: "Collector",
        pro: "Pro",
        premium: "Premium",
      };

      const totalSpent = purchases.reduce((sum, p) => sum + (p.amount || 0), 0);

      const now = new Date();
      const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
      const planUsed = purchases.filter(
        (p) => new Date(p.createdAt) >= monthStart,
      ).length;

      res.send({
        worksCollected: purchases.length,
        totalSpent: `$${totalSpent.toLocaleString()}`,
        currentPlan: planNameMap[planId],
        planId,
        planUsed,
        planMax: planMaxMap[planId],
      });
    });

    app.get("/api/collector/purchases", verifyToken, async (req, res) => {
      const userId = req.decoded.id || req.decoded.sub;
      const result = await purchaseCollection
        .find({ userId })
        .sort({ createdAt: -1 })
        .toArray();

      const isValidObjectId = (id) => /^[a-f\d]{24}$/i.test(id);

      const formatted = await Promise.all(
        result.map(async (p) => {
          let artistId = p.artistId;

          if (!isValidObjectId(artistId)) {
            const artistDoc = await artistCollection.findOne({
              name: p.artist,
            });
            if (artistDoc) artistId = artistDoc._id.toString();
          }

          return {
            id: p._id.toString(),

            artworkId: p.artworkId,
            artwork: p.artwork,
            artist: p.artist,
            artistId,
            date: p.date,
            amount: p.amount,
            image: p.image,
          };
        }),
      );

      res.send(formatted);
    });

    app.get("/api/collector/gallery", verifyToken, async (req, res) => {
      const userId = req.decoded.id || req.decoded.sub;
      const purchases = await purchaseCollection
        .find({ userId })
        .sort({ createdAt: -1 })
        .toArray();

      const isValidObjectId = (id) => /^[a-f\d]{24}$/i.test(id);

      const gallery = await Promise.all(
        purchases.map(async (p) => {
          let artistId = p.artistId;

          if (!isValidObjectId(artistId)) {
            const artistDoc = await artistCollection.findOne({
              name: p.artist,
            });
            if (artistDoc) artistId = artistDoc._id.toString();
          }

          return {
            id: p._id.toString(),
            name: p.artwork,
            price: p.amount,
            artist: p.artist,
            artistId,
            category: p.category,
            image: p.image,
          };
        }),
      );

      res.send(gallery);
    });

    app.get("/api/collector/plan", verifyToken, async (req, res) => {
      const userId = req.decoded.id || req.decoded.sub;
      const subscription = await subscriptionCollection.findOne({ userId });
      res.send({ planId: subscription?.planId || "collector" });
    });

    app.patch("/api/collector/plan", verifyToken, async (req, res) => {
      const userId = req.decoded.id || req.decoded.sub;
      const { planId } = req.body;

      if (!["collector", "pro", "premium"].includes(planId)) {
        return res.status(400).json({ message: "Invalid plan" });
      }

      await subscriptionCollection.updateOne(
        { userId },
        { $set: { planId, updatedAt: new Date() } },
        { upsert: true },
      );

      res.send({ success: true, planId });
    });

    app.get(
      "/api/artist/stats",
      verifyToken,
      verifyArtist,
      async (req, res) => {
        const artistId = req.decoded.id || req.decoded.sub;

        const allWorks = await artworkCollection.find({ artistId }).toArray();
        const liveWorks = allWorks.filter((a) => a.status === "published");
        const sales = await purchaseCollection.find({ artistId }).toArray();
        const revenue = sales.reduce((sum, s) => sum + (s.amount || 0), 0);

        res.send({
          totalWorks: allWorks.length,
          liveNow: liveWorks.length,
          sold: sales.length,
          revenue,
        });
      },
    );

    app.get(
      "/api/artist/sales",
      verifyToken,
      verifyArtist,
      async (req, res) => {
        const artistId = req.decoded.id || req.decoded.sub;
        const sales = await purchaseCollection
          .find({ artistId })
          .sort({ createdAt: -1 })
          .toArray();

        const userIds = [...new Set(sales.map((s) => s.userId))];
        const users = await userCollection
          .find({
            _id: {
              $in: userIds
                .map((id) => {
                  try {
                    return new ObjectId(id);
                  } catch {
                    return null;
                  }
                })
                .filter(Boolean),
            },
          })
          .toArray();

        const userMap = {};
        users.forEach((u) => {
          userMap[u._id.toString()] = u.name ?? u.email ?? "Unknown";
        });

        const formatted = sales.map((s) => ({
          id: s._id.toString(),
          artwork: s.artwork,
          collector: userMap[s.userId] ?? s.userId,
          date: s.date,
          amount: s.amount,
        }));

        res.send(formatted);
      },
    );

    app.get(
      "/api/artist/profile",
      verifyToken,
      verifyArtist,
      async (req, res) => {
        const artistId = req.decoded.id || req.decoded.sub;
        const artist = await artistCollection.findOne({ userId: artistId });
        if (!artist) return res.send({});
        res.send({
          location: artist.location ?? "",
          bio: artist.bio ?? "",
          avatar: artist.avatar ?? "",
        });
      },
    );

    app.post("/api/collector/purchases", verifyToken, async (req, res) => {
      const userId = req.decoded.id || req.decoded.sub;
      const role = req.decoded.role;
      if (role === "artist" || role === "admin") {
        return res.status(403).json({
          message: "Artists and admins cannot purchase artworks.",
        });
      }

      const { artworkId, artwork, artist, artistId, amount, image, category } =
        req.body;

      const subscription = await subscriptionCollection.findOne({ userId });
      const planId = subscription?.planId || "collector";
      const planMaxMap = { collector: 3, pro: 9, premium: 9999 };
      const planMax = planMaxMap[planId];

      const now = new Date();
      const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
      const monthlyCount = await purchaseCollection.countDocuments({
        userId,
        createdAt: { $gte: monthStart },
      });

      if (monthlyCount >= planMax) {
        return res.status(403).json({
          message: "Monthly limit reached. Upgrade your plan to buy more.",
        });
      }

      const already = await purchaseCollection.findOne({ userId, artworkId });
      if (already) {
        return res
          .status(409)
          .json({ message: "You already own this artwork." });
      }

      let artistDoc = await artistCollection.findOne({ userId: artistId });
      if (!artistDoc) {
        try {
          artistDoc = await artistCollection.findOne({
            _id: new ObjectId(artistId),
          });
        } catch {}
      }
      if (!artistDoc) {
        artistDoc = await artistCollection.findOne({ name: artist });
      }
      const artistPageId = artistDoc ? artistDoc._id.toString() : artistId;

      const result = await purchaseCollection.insertOne({
        userId,
        artworkId,
        artwork,
        artist,
        artistId: artistPageId,
        amount,
        image,
        category,
        date: new Date().toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
          year: "numeric",
        }),
        createdAt: new Date(),
      });

      res.send({ success: true, insertedId: result.insertedId });
    });

    app.get("/api/admin/stats", verifyToken, verifyAdmin, async (req, res) => {
      const [userCount, artworkCount, purchases] = await Promise.all([
        userCollection.countDocuments(),
        artworkCollection.countDocuments(),
        purchaseCollection.find().toArray(),
      ]);
      const revenue = purchases.reduce((sum, p) => sum + (p.amount || 0), 0);
      const artistCount = await userCollection.countDocuments({
        role: "artist",
      });
      res.send({
        users: userCount,
        artworks: artworkCount,
        transactions: purchases.length,
        revenue,
        artists: artistCount,
      });
    });

    app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
      const users = await userCollection
        .find()
        .sort({ createdAt: -1 })
        .toArray();
      res.send(
        users.map((u) => ({
          id: u._id.toString(),
          name: u.name ?? "",
          email: u.email ?? "",
          role: u.role ?? "collector",
          createdAt: u.createdAt
            ? new Date(u.createdAt).toLocaleDateString("en-US", {
                month: "short",
                day: "numeric",
                year: "numeric",
              })
            : "—",
        })),
      );
    });

    app.get(
      "/api/admin/artworks",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const artworks = await artworkCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();
        res.send(
          artworks.map((a) => ({
            _id: a._id.toString(),
            title: a.title,
            artistName: a.artistName ?? "",
            artistId: a.artistId ?? "",
            category: a.category,
            price: a.price,
            status: a.status,
            image: a.image,
          })),
        );
      },
    );

    app.delete(
      "/api/admin/artworks/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const result = await artworkCollection.deleteOne({
          _id: new ObjectId(id),
        });
        if (result.deletedCount === 0)
          return res.status(404).json({ message: "Artwork not found" });
        res.send({ success: true });
      },
    );

    app.get(
      "/api/admin/transactions",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const purchases = await purchaseCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();

        const userIds = [...new Set(purchases.map((p) => p.userId))];
        const users = await userCollection
          .find({
            _id: {
              $in: userIds
                .map((id) => {
                  try {
                    return new ObjectId(id);
                  } catch {
                    return null;
                  }
                })
                .filter(Boolean),
            },
          })
          .toArray();

        const userMap = {};
        users.forEach((u) => {
          userMap[u._id.toString()] = u.name ?? u.email ?? "Unknown";
        });

        res.send(
          purchases.map((p) => ({
            id: p._id.toString(),
            artwork: p.artwork,
            collector: userMap[p.userId] ?? p.userId,
            artist: p.artist,
            amount: p.amount,
            date: p.date,
          })),
        );
      },
    );

    app.get(
      "/api/admin/sales-over-time",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const purchases = await purchaseCollection.find().toArray();
        const monthMap = {};
        purchases.forEach((p) => {
          const d = new Date(p.createdAt);
          const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
          const label = d.toLocaleDateString("en-US", { month: "short" });
          if (!monthMap[key])
            monthMap[key] = { key, month: label, revenue: 0, count: 0 };
          monthMap[key].revenue += p.amount || 0;
          monthMap[key].count += 1;
        });
        const sorted = Object.values(monthMap).sort((a, b) =>
          a.key.localeCompare(b.key),
        );
        res.send(sorted.slice(-12));
      },
    );

    app.get(
      "/api/admin/categories",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const purchases = await purchaseCollection.find().toArray();
        const catMap = {};
        purchases.forEach((p) => {
          const cat = p.category || "Other";
          catMap[cat] = (catMap[cat] || 0) + 1;
        });
        res.send(
          Object.entries(catMap).map(([name, count]) => ({ name, count })),
        );
      },
    );

    app.patch(
      "/api/admin/users/:id/role",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { role } = req.body;

        if (!["collector", "artist", "admin"].includes(role)) {
          return res.status(400).json({ message: "Invalid role" });
        }

        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role, updatedAt: new Date() } },
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.send({ success: true });
      },
    );

    app.post("/api/stripe/artwork-session", verifyToken, async (req, res) => {
      const { artworkId, artwork, artist, artistId, amount, image, category } =
        req.body;
      const userId = req.decoded.id || req.decoded.sub;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        mode: "payment",
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: Math.round(amount * 100),
              product_data: {
                name: artwork,
                description: `By ${artist}`,
                images: [image],
              },
            },
            quantity: 1,
          },
        ],
        metadata: {
          type: "artwork",
          userId,
          artworkId,
          artwork,
          artist,
          artistId,
          amount: String(amount),
          image,
          category,
        },
        success_url: `${process.env.CLIENT_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_URL}/cancel`,
      });

      res.send({ url: session.url });
    });

    app.post(
      "/api/stripe/subscription-session",
      verifyToken,
      async (req, res) => {
        const { planId } = req.body;
        const userId = req.decoded.id || req.decoded.sub;

        const planPriceMap = { pro: 999, premium: 1999 };
        const planNameMap = { pro: "Pro Plan", premium: "Premium Plan" };

        if (!planPriceMap[planId]) {
          return res.status(400).json({ message: "Invalid plan" });
        }

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          line_items: [
            {
              price_data: {
                currency: "usd",
                unit_amount: planPriceMap[planId],
                product_data: {
                  name: planNameMap[planId],
                  description: `ArtHub ${planNameMap[planId]} subscription`,
                },
              },
              quantity: 1,
            },
          ],
          metadata: {
            type: "subscription",
            userId,
            planId,
          },
          success_url: `${process.env.CLIENT_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_URL}/cancel`,
        });

        res.send({ url: session.url });
      },
    );

    app.post("/api/stripe/verify-session", verifyToken, async (req, res) => {
      const { sessionId } = req.body;

      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.payment_status !== "paid") {
        return res.status(400).json({ message: "Payment not completed." });
      }

      const meta = session.metadata;

      if (meta.type === "artwork") {
        const {
          userId,
          artworkId,
          artwork,
          artist,
          artistId,
          amount,
          image,
          category,
        } = meta;

        const already = await purchaseCollection.findOne({ userId, artworkId });
        if (already) {
          return res.send({ success: true, alreadyRecorded: true });
        }

        let artistDoc = await artistCollection.findOne({ userId: artistId });
        if (!artistDoc) {
          try {
            artistDoc = await artistCollection.findOne({
              _id: new ObjectId(artistId),
            });
          } catch {}
        }
        if (!artistDoc) {
          artistDoc = await artistCollection.findOne({ name: artist });
        }
        const artistPageId = artistDoc ? artistDoc._id.toString() : artistId;

        await purchaseCollection.insertOne({
          userId,
          artworkId,
          artwork,
          artist,
          artistId: artistPageId,
          amount: Number(amount),
          image,
          category,
          date: new Date().toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
            year: "numeric",
          }),
          createdAt: new Date(),
        });

        return res.send({ success: true, type: "artwork" });
      }

      if (meta.type === "subscription") {
        const { userId, planId } = meta;

        await subscriptionCollection.updateOne(
          { userId },
          { $set: { planId, updatedAt: new Date() } },
          { upsert: true },
        );

        return res.send({ success: true, type: "subscription", planId });
      }

      res.status(400).json({ message: "Unknown session type." });
    });
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("This is ArtHub server");
});

app.listen(PORT, () => {
  console.log(`Example app listening on port ${PORT}`);
});
