const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

// =========================
// POSTGRESQL
// =========================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function query(sql, params = []) {
    return pool.query(sql, params);
}

async function initDatabase() {
    await query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            token TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS likes (
            id SERIAL PRIMARY KEY,
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(post_id, user_id)
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS friend_requests (
            id SERIAL PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS friends (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, friend_id)
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read INTEGER NOT NULL DEFAULT 0
        )
    `);

    console.log("✅ PostgreSQL prêt.");
}

// =========================
// MIDDLEWARE
// =========================

app.use(express.json());
app.use(express.static(path.join(__dirname)));

const onlineUsers = new Map();

// =========================
// AUTHENTIFICATION
// =========================

async function getUserFromToken(token) {
    if (!token) return null;

    const result = await query(`
        SELECT users.*
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = $1
    `, [token]);

    return result.rows[0] || null;
}

async function authMiddleware(req, res, next) {
    try {
        const token = req.headers.authorization;
        const user = await getUserFromToken(token);

        if (!user) {
            return res.status(401).json({
                error: "Non authentifié"
            });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Erreur d'authentification."
        });
    }
}

// =========================
// INSCRIPTION
// =========================

app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                error: "Tous les champs sont obligatoires."
            });
        }

        const existing = await query(
            `SELECT id FROM users WHERE email = $1`,
            [email.trim()]
        );

        if (existing.rows.length > 0) {
            return res.status(400).json({
                error: "Cette adresse email existe déjà."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await query(`
            INSERT INTO users (name, email, password)
            VALUES ($1, $2, $3)
            RETURNING id
        `, [
            name.trim(),
            email.trim(),
            hashedPassword
        ]);

        res.json({
            success: true,
            userId: result.rows[0].id
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Erreur lors de l'inscription."
        });
    }
});

// =========================
// CONNEXION
// =========================

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await query(
            `SELECT * FROM users WHERE email = $1`,
            [email]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({
                error: "Email ou mot de passe incorrect."
            });
        }

        const passwordCorrect = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordCorrect) {
            return res.status(401).json({
                error: "Email ou mot de passe incorrect."
            });
        }

        const token = crypto.randomBytes(32).toString("hex");

        await query(`
            INSERT INTO sessions (token, user_id)
            VALUES ($1, $2)
        `, [token, user.id]);

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Erreur de connexion."
        });
    }
});

// =========================
// UTILISATEUR CONNECTÉ
// =========================

app.get("/api/me", authMiddleware, (req, res) => {
    res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email
    });
});

// =========================
// DÉCONNEXION
// =========================

app.post("/api/logout", authMiddleware, async (req, res) => {
    try {
        await query(
            `DELETE FROM sessions WHERE token = $1`,
            [req.headers.authorization]
        );

        res.json({ success: true });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Erreur de déconnexion."
        });
    }
});

// =========================
// PROFIL
// =========================

app.put("/api/profile", authMiddleware, async (req, res) => {
    const { name, email } = req.body;

    if (!name || !email) {
        return res.status(400).json({
            error: "Nom et email obligatoires."
        });
    }

    try {
        await query(`
            UPDATE users
            SET name = $1, email = $2
            WHERE id = $3
        `, [
            name.trim(),
            email.trim(),
            req.user.id
        ]);

        res.json({ success: true });

    } catch (error) {
        console.error(error);
        res.status(400).json({
            error: "Cet email est peut-être déjà utilisé."
        });
    }
});

// =========================
// UTILISATEURS
// =========================

app.get("/api/users", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT id, name, email
        FROM users
        WHERE id != $1
        ORDER BY name
    `, [req.user.id]);

    res.json(result.rows.map(user => ({
        ...user,
        online: onlineUsers.has(user.id)
    })));
});

app.get("/api/users/search", authMiddleware, async (req, res) => {
    const q = (req.query.q || "").trim();

    if (!q) return res.json([]);

    const result = await query(`
        SELECT id, name, email
        FROM users
        WHERE id != $1
        AND (
            name ILIKE $2
            OR email ILIKE $2
        )
        ORDER BY name
    `, [
        req.user.id,
        `%${q}%`
    ]);

    res.json(result.rows.map(user => ({
        ...user,
        online: onlineUsers.has(user.id)
    })));
});

app.get("/api/users/:id", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT id, name, email
        FROM users
        WHERE id = $1
    `, [req.params.id]);

    const user = result.rows[0];

    if (!user) {
        return res.status(404).json({
            error: "Utilisateur introuvable."
        });
    }

    res.json({
        ...user,
        online: onlineUsers.has(user.id)
    });
});

app.get("/api/users/:id/online-status", authMiddleware, (req, res) => {
    res.json({
        online: onlineUsers.has(Number(req.params.id))
    });
});

// =========================
// PUBLICATIONS
// =========================

app.post("/api/posts", authMiddleware, async (req, res) => {
    const content = (req.body.content || "").trim();

    if (!content) {
        return res.status(400).json({
            error: "La publication est vide."
        });
    }

    const result = await query(`
        INSERT INTO posts (user_id, content)
        VALUES ($1, $2)
        RETURNING id
    `, [
        req.user.id,
        content
    ]);

    res.json({
        success: true,
        postId: result.rows[0].id
    });
});

app.get("/api/posts", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT
            posts.id,
            posts.content,
            posts.created_at,
            users.id AS user_id,
            users.name,

            (
                SELECT COUNT(*)
                FROM likes
                WHERE likes.post_id = posts.id
            ) AS likes_count,

            (
                SELECT COUNT(*)
                FROM comments
                WHERE comments.post_id = posts.id
            ) AS comments_count,

            EXISTS (
                SELECT 1
                FROM likes
                WHERE likes.post_id = posts.id
                AND likes.user_id = $1
            ) AS liked

        FROM posts

        JOIN users
        ON users.id = posts.user_id

        ORDER BY posts.id DESC
    `, [req.user.id]);

    res.json(result.rows);
});

app.delete("/api/posts/:id", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT *
        FROM posts
        WHERE id = $1
    `, [req.params.id]);

    const post = result.rows[0];

    if (!post) {
        return res.status(404).json({
            error: "Publication introuvable."
        });
    }

    if (post.user_id !== req.user.id) {
        return res.status(403).json({
            error: "Vous ne pouvez pas supprimer cette publication."
        });
    }

    await query(`
        DELETE FROM posts
        WHERE id = $1
    `, [req.params.id]);

    res.json({
        success: true
    });
});

// =========================
// LIKES
// =========================

app.post("/api/posts/:id/like", authMiddleware, async (req, res) => {
    const postId = Number(req.params.id);

    const existing = await query(`
        SELECT id
        FROM likes
        WHERE post_id = $1
        AND user_id = $2
    `, [
        postId,
        req.user.id
    ]);

    if (existing.rows.length > 0) {
        await query(`
            DELETE FROM likes
            WHERE id = $1
        `, [existing.rows[0].id]);

        return res.json({
            liked: false
        });
    }

    await query(`
        INSERT INTO likes (post_id, user_id)
        VALUES ($1, $2)
    `, [
        postId,
        req.user.id
    ]);

    res.json({
        liked: true
    });
});

// =========================
// COMMENTAIRES
// =========================

app.get("/api/posts/:id/comments", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT
            comments.id,
            comments.content,
            comments.created_at,
            users.id AS user_id,
            users.name
        FROM comments
        JOIN users
        ON users.id = comments.user_id
        WHERE comments.post_id = $1
        ORDER BY comments.id ASC
    `, [req.params.id]);

    res.json(result.rows);
});

app.post("/api/posts/:id/comments", authMiddleware, async (req, res) => {
    const content = (req.body.content || "").trim();

    if (!content) {
        return res.status(400).json({
            error: "Commentaire vide."
        });
    }

    const post = await query(`
        SELECT id
        FROM posts
        WHERE id = $1
    `, [req.params.id]);

    if (!post.rows.length) {
        return res.status(404).json({
            error: "Publication introuvable."
        });
    }

    await query(`
        INSERT INTO comments (post_id, user_id, content)
        VALUES ($1, $2, $3)
    `, [
        req.params.id,
        req.user.id,
        content
    ]);

    res.json({
        success: true
    });
});

app.delete("/api/comments/:id", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT *
        FROM comments
        WHERE id = $1
    `, [req.params.id]);

    const comment = result.rows[0];

    if (!comment) {
        return res.status(404).json({
            error: "Commentaire introuvable."
        });
    }

    if (comment.user_id !== req.user.id) {
        return res.status(403).json({
            error: "Vous ne pouvez pas supprimer ce commentaire."
        });
    }

    await query(`
        DELETE FROM comments
        WHERE id = $1
    `, [req.params.id]);

    res.json({
        success: true
    });
});

// =========================
// AMIS
// =========================

app.get("/api/users/:id/friend-status", authMiddleware, async (req, res) => {
    const targetId = Number(req.params.id);

    if (targetId === req.user.id) {
        return res.json({
            status: "self"
        });
    }

    const friendship = await query(`
        SELECT id
        FROM friends
        WHERE user_id = $1
        AND friend_id = $2
    `, [
        req.user.id,
        targetId
    ]);

    if (friendship.rows.length) {
        return res.json({
            status: "friends"
        });
    }

    const outgoing = await query(`
        SELECT id
        FROM friend_requests
        WHERE sender_id = $1
        AND receiver_id = $2
        AND status = 'pending'
    `, [
        req.user.id,
        targetId
    ]);

    if (outgoing.rows.length) {
        return res.json({
            status: "outgoing_pending",
            requestId: outgoing.rows[0].id
        });
    }

    const incoming = await query(`
        SELECT id
        FROM friend_requests
        WHERE sender_id = $1
        AND receiver_id = $2
        AND status = 'pending'
    `, [
        targetId,
        req.user.id
    ]);

    if (incoming.rows.length) {
        return res.json({
            status: "incoming_pending",
            requestId: incoming.rows[0].id
        });
    }

    res.json({
        status: "none"
    });
});

app.post("/api/friend-requests/:id", authMiddleware, async (req, res) => {
    const receiverId = Number(req.params.id);

    if (receiverId === req.user.id) {
        return res.status(400).json({
            error: "Impossible de vous ajouter vous-même."
        });
    }

    const receiver = await query(`
        SELECT id, name
        FROM users
        WHERE id = $1
    `, [receiverId]);

    if (!receiver.rows.length) {
        return res.status(404).json({
            error: "Utilisateur introuvable."
        });
    }

    const existingFriend = await query(`
        SELECT id
        FROM friends
        WHERE user_id = $1
        AND friend_id = $2
    `, [
        req.user.id,
        receiverId
    ]);

    if (existingFriend.rows.length) {
        return res.status(400).json({
            error: "Vous êtes déjà amis."
        });
    }

    const existingRequest = await query(`
        SELECT id
        FROM friend_requests
        WHERE sender_id = $1
        AND receiver_id = $2
        AND status = 'pending'
    `, [
        req.user.id,
        receiverId
    ]);

    if (existingRequest.rows.length) {
        return res.status(400).json({
            error: "Demande déjà envoyée."
        });
    }

    const reverseRequest = await query(`
        SELECT id
        FROM friend_requests
        WHERE sender_id = $1
        AND receiver_id = $2
        AND status = 'pending'
    `, [
        receiverId,
        req.user.id
    ]);

    if (reverseRequest.rows.length) {
        return res.status(400).json({
            error: "Cette personne vous a déjà envoyé une demande."
        });
    }

    const result = await query(`
        INSERT INTO friend_requests
        (sender_id, receiver_id)
        VALUES ($1, $2)
        RETURNING id
    `, [
        req.user.id,
        receiverId
    ]);

    const socketId = onlineUsers.get(receiverId);

    if (socketId) {
        io.to(socketId).emit("friend_request", {
            requestId: result.rows[0].id,
            senderId: req.user.id,
            senderName: req.user.name
        });
    }

    res.json({
        success: true
    });
});

app.get("/api/friend-requests", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT
            friend_requests.id,
            friend_requests.created_at,
            users.id AS user_id,
            users.name,
            users.email
        FROM friend_requests
        JOIN users
        ON users.id = friend_requests.sender_id
        WHERE friend_requests.receiver_id = $1
        AND friend_requests.status = 'pending'
        ORDER BY friend_requests.id DESC
    `, [req.user.id]);

    res.json(result.rows);
});

app.get("/api/friend-requests/count", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT COUNT(*)::int AS count
        FROM friend_requests
        WHERE receiver_id = $1
        AND status = 'pending'
    `, [req.user.id]);

    res.json({
        count: result.rows[0].count
    });
});

app.post("/api/friend-requests/:id/accept", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT *
        FROM friend_requests
        WHERE id = $1
        AND receiver_id = $2
        AND status = 'pending'
    `, [
        req.params.id,
        req.user.id
    ]);

    const request = result.rows[0];

    if (!request) {
        return res.status(404).json({
            error: "Demande introuvable."
        });
    }

    await query(`
        UPDATE friend_requests
        SET status = 'accepted'
        WHERE id = $1
    `, [request.id]);

    await query(`
        INSERT INTO friends (user_id, friend_id)
        VALUES ($1, $2)
        ON CONFLICT (user_id, friend_id) DO NOTHING
    `, [
        request.sender_id,
        request.receiver_id
    ]);

    await query(`
        INSERT INTO friends (user_id, friend_id)
        VALUES ($1, $2)
        ON CONFLICT (user_id, friend_id) DO NOTHING
    `, [
        request.receiver_id,
        request.sender_id
    ]);

    const socketId = onlineUsers.get(request.sender_id);

    if (socketId) {
        io.to(socketId).emit("friend_request_accepted", {
            userId: req.user.id,
            userName: req.user.name
        });
    }

    res.json({
        success: true
    });
});

app.post("/api/friend-requests/:id/reject", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT id
        FROM friend_requests
        WHERE id = $1
        AND receiver_id = $2
        AND status = 'pending'
    `, [
        req.params.id,
        req.user.id
    ]);

    if (!result.rows.length) {
        return res.status(404).json({
            error: "Demande introuvable."
        });
    }

    await query(`
        UPDATE friend_requests
        SET status = 'rejected'
        WHERE id = $1
    `, [req.params.id]);

    res.json({
        success: true
    });
});

app.get("/api/friends", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT
            users.id,
            users.name,
            users.email
        FROM friends
        JOIN users
        ON users.id = friends.friend_id
        WHERE friends.user_id = $1
        ORDER BY users.name
    `, [req.user.id]);

    res.json(result.rows.map(friend => ({
        ...friend,
        online: onlineUsers.has(friend.id)
    })));
});

app.delete("/api/friends/:id", authMiddleware, async (req, res) => {
    const friendId = Number(req.params.id);

    await query(`
        DELETE FROM friends
        WHERE
            (user_id = $1 AND friend_id = $2)
            OR
            (user_id = $2 AND friend_id = $1)
    `, [
        req.user.id,
        friendId
    ]);

    res.json({
        success: true
    });
});

// =========================
// MESSAGES
// =========================

app.get("/api/messages/unread-count", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT COUNT(*)::int AS count
        FROM messages
        WHERE receiver_id = $1
        AND is_read = 0
    `, [req.user.id]);

    res.json({
        count: result.rows[0].count
    });
});

app.post("/api/messages", authMiddleware, async (req, res) => {
    const receiverId = Number(req.body.receiver_id);
    const content = (req.body.content || "").trim();

    if (!receiverId || !content) {
        return res.status(400).json({
            error: "Destinataire et message obligatoires."
        });
    }

    if (receiverId === req.user.id) {
        return res.status(400).json({
            error: "Vous ne pouvez pas vous envoyer un message."
        });
    }

    const receiver = await query(`
        SELECT id, name
        FROM users
        WHERE id = $1
    `, [receiverId]);

    if (!receiver.rows.length) {
        return res.status(404).json({
            error: "Destinataire introuvable."
        });
    }

    const result = await query(`
        INSERT INTO messages
        (sender_id, receiver_id, content, created_at, is_read)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP, 0)
        RETURNING id, created_at
    `, [
        req.user.id,
        receiverId,
        content
    ]);

    const message = {
        messageId: result.rows[0].id,
        senderId: req.user.id,
        senderName: req.user.name,
        receiverId,
        content,
        createdAt: result.rows[0].created_at
    };

    const socketId = onlineUsers.get(receiverId);

    if (socketId) {
        io.to(socketId).emit("new_message", message);
    }

    res.json({
        success: true,
        message
    });
});

app.get("/api/messages/:userId", authMiddleware, async (req, res) => {
    const otherUserId = Number(req.params.userId);

    const otherUser = await query(`
        SELECT id, name, email
        FROM users
        WHERE id = $1
    `, [otherUserId]);

    if (!otherUser.rows.length) {
        return res.status(404).json({
            error: "Utilisateur introuvable."
        });
    }

    const result = await query(`
        SELECT
            messages.id,
            messages.sender_id,
            messages.receiver_id,
            messages.content,
            messages.created_at,
            messages.is_read,
            sender.name AS sender_name,
            receiver.name AS receiver_name
        FROM messages
        JOIN users AS sender
        ON sender.id = messages.sender_id
        JOIN users AS receiver
        ON receiver.id = messages.receiver_id
        WHERE
            (
                messages.sender_id = $1
                AND messages.receiver_id = $2
            )
            OR
            (
                messages.sender_id = $2
                AND messages.receiver_id = $1
            )
        ORDER BY messages.id ASC
    `, [
        req.user.id,
        otherUserId
    ]);

    await query(`
        UPDATE messages
        SET is_read = 1
        WHERE sender_id = $1
        AND receiver_id = $2
        AND is_read = 0
    `, [
        otherUserId,
        req.user.id
    ]);

    res.json(result.rows);
});

app.get("/api/conversations", authMiddleware, async (req, res) => {
    const result = await query(`
        SELECT
            u.id,
            u.name,
            u.email,
            MAX(m.created_at) AS last_message_at,

            (
                SELECT m2.content
                FROM messages m2
                WHERE
                    (
                        m2.sender_id = $1
                        AND m2.receiver_id = u.id
                    )
                    OR
                    (
                        m2.sender_id = u.id
                        AND m2.receiver_id = $1
                    )
                ORDER BY m2.id DESC
                LIMIT 1
            ) AS last_message,

            (
                SELECT COUNT(*)::int
                FROM messages m3
                WHERE m3.sender_id = u.id
                AND m3.receiver_id = $1
                AND m3.is_read = 0
            ) AS unread_count

        FROM users u

        JOIN messages m
        ON
            (
                m.sender_id = $1
                AND m.receiver_id = u.id
            )
            OR
            (
                m.sender_id = u.id
                AND m.receiver_id = $1
            )

        GROUP BY u.id, u.name, u.email
        ORDER BY last_message_at DESC
    `, [req.user.id]);

    res.json(result.rows.map(conversation => ({
        ...conversation,
        online: onlineUsers.has(conversation.id)
    })));
});

// =========================
// NOTIFICATIONS
// =========================

function sendUserNotification(userId, type, data) {
    const socketId = onlineUsers.get(Number(userId));

    if (!socketId) return;

    io.to(socketId).emit(type, data);
}

// =========================
// SOCKET.IO
// =========================

io.on("connection", async (socket) => {
    try {
        const token = socket.handshake.auth.token;
        const user = await getUserFromToken(token);

        if (!user) {
            socket.disconnect();
            return;
        }

        const userId = user.id;

        const previousSocketId = onlineUsers.get(userId);

        if (
            previousSocketId &&
            previousSocketId !== socket.id
        ) {
            const previousSocket =
                io.sockets.sockets.get(previousSocketId);

            if (previousSocket) {
                previousSocket.disconnect();
            }
        }

        onlineUsers.set(userId, socket.id);

        console.log(`🟢 ${user.name} est en ligne.`);

        socket.broadcast.emit("user_online", {
            userId,
            userName: user.name
        });

        socket.on("friend_request_sent", (data) => {
            if (!data || !data.receiverId) return;

            sendUserNotification(
                data.receiverId,
                "friend_request",
                {
                    senderId: userId,
                    senderName: user.name
                }
            );
        });

        socket.on("message_sent", (data) => {
            if (!data || !data.receiverId) return;

            sendUserNotification(
                data.receiverId,
                "new_message",
                {
                    messageId: data.messageId,
                    senderId: userId,
                    senderName: user.name,
                    receiverId: data.receiverId,
                    content: data.content
                }
            );
        });

        socket.on("disconnect", () => {
            if (onlineUsers.get(userId) === socket.id) {
                onlineUsers.delete(userId);

                console.log(`⚫ ${user.name} est hors ligne.`);

                socket.broadcast.emit("user_offline", {
                    userId,
                    userName: user.name
                });
            }
        });

    } catch (error) {
        console.error("Socket error:", error);
        socket.disconnect();
    }
});

// =========================
// PAGE PRINCIPALE
// =========================

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "index.html")
    );
});

// =========================
// DÉMARRAGE
// =========================

async function startServer() {
    try {
        await initDatabase();

        server.listen(
            PORT,
            "0.0.0.0",
            () => {
                console.log(
                    `🚀 CommunityOS démarré sur le port ${PORT}`
                );
            }
        );

    } catch (error) {
        console.error(
            "❌ Impossible de démarrer CommunityOS :",
            error
        );

        process.exit(1);
    }
}

startServer();
