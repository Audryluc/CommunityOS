const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;

const db = new Database("users.db");

app.use(express.json());
app.use(express.static(__dirname));

// ==========================================
// TABLES
// ==========================================

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(post_id, user_id),
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, friend_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (friend_id) REFERENCES users(id)
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_read INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )
`).run();

// ==========================================
// AUTHENTIFICATION
// ==========================================

function getUserFromToken(req) {
    const token = req.headers.authorization;

    if (!token) {
        return null;
    }

    const session = db.prepare(`
        SELECT users.id, users.name, users.email
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
    `).get(token);

    return session || null;
}

// ==========================================
// SOCKET.IO - UTILISATEUR CONNECTÉ
// ==========================================

const onlineUsers = new Map();

io.on("connection", (socket) => {
    const token = socket.handshake.auth.token;

    if (!token) {
        socket.disconnect();
        return;
    }

    const session = db.prepare(`
        SELECT user_id
        FROM sessions
        WHERE token = ?
    `).get(token);

    if (!session) {
        socket.disconnect();
        return;
    }

    const userId = session.user_id;

    onlineUsers.set(userId, socket.id);

    console.log(`🟢 Utilisateur ${userId} connecté en temps réel.`);

    socket.on("disconnect", () => {
        if (onlineUsers.get(userId) === socket.id) {
            onlineUsers.delete(userId);
        }

        console.log(`🔴 Utilisateur ${userId} déconnecté.`);
    });
});

// ==========================================
// INSCRIPTION
// ==========================================

app.post("/api/register", async (req, res) => {
    try {
        const name = (req.body.name || "").trim();
        const email = (req.body.email || "").trim().toLowerCase();
        const password = req.body.password || "";

        if (!name || !email || !password) {
            return res.status(400).json({
                error: "Tous les champs sont obligatoires."
            });
        }

        const existingUser = db.prepare(`
            SELECT id
            FROM users
            WHERE email = ?
        `).get(email);

        if (existingUser) {
            return res.status(400).json({
                error: "Cet email est déjà utilisé."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = db.prepare(`
            INSERT INTO users (name, email, password)
            VALUES (?, ?, ?)
        `).run(name, email, hashedPassword);

        res.json({
            success: true,
            userId: result.lastInsertRowid
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Erreur lors de la création du compte."
        });
    }
});

// ==========================================
// CONNEXION
// ==========================================

app.post("/api/login", async (req, res) => {
    try {
        const email = (req.body.email || "").trim().toLowerCase();
        const password = req.body.password || "";

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE email = ?
        `).get(email);

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

        db.prepare(`
            INSERT INTO sessions (token, user_id)
            VALUES (?, ?)
        `).run(token, user.id);

        res.json({
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
            error: "Erreur lors de la connexion."
        });
    }
});

// ==========================================
// UTILISATEUR CONNECTÉ
// ==========================================

app.get("/api/me", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    res.json(user);
});

// ==========================================
// DÉCONNEXION
// ==========================================

app.post("/api/logout", (req, res) => {
    const token = req.headers.authorization;

    if (token) {
        db.prepare(`
            DELETE FROM sessions
            WHERE token = ?
        `).run(token);
    }

    res.json({
        success: true
    });
});

// ==========================================
// LISTE DES UTILISATEURS
// ==========================================

app.get("/api/users", (req, res) => {
    const users = db.prepare(`
        SELECT id, name, email
        FROM users
        ORDER BY id DESC
    `).all();

    res.json(users);
});

// ==========================================
// RECHERCHE UTILISATEURS
// ==========================================

app.get("/api/users/search", (req, res) => {
    const q = (req.query.q || "").trim();

    if (!q) {
        return res.json([]);
    }

    const users = db.prepare(`
        SELECT id, name, email
        FROM users
        WHERE name LIKE ?
           OR email LIKE ?
        ORDER BY name ASC
        LIMIT 20
    `).all(`%${q}%`, `%${q}%`);

    res.json(users);
});

// ==========================================
// PROFIL UTILISATEUR
// ==========================================

app.get("/api/users/:id", (req, res) => {
    const userId = Number(req.params.id);

    const user = db.prepare(`
        SELECT id, name, email
        FROM users
        WHERE id = ?
    `).get(userId);

    if (!user) {
        return res.status(404).json({
            error: "Utilisateur introuvable."
        });
    }

    res.json(user);
});

// ==========================================
// STATUT AMI
// ==========================================

app.get("/api/users/:id/friend-status", (req, res) => {
    const currentUser = getUserFromToken(req);

    if (!currentUser) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const otherUserId = Number(req.params.id);

    if (currentUser.id === otherUserId) {
        return res.json({
            status: "self"
        });
    }

    const friendship = db.prepare(`
        SELECT id
        FROM friends
        WHERE user_id = ?
          AND friend_id = ?
    `).get(currentUser.id, otherUserId);

    if (friendship) {
        return res.json({
            status: "friends"
        });
    }

    const outgoing = db.prepare(`
        SELECT id
        FROM friend_requests
        WHERE sender_id = ?
          AND receiver_id = ?
          AND status = 'pending'
    `).get(currentUser.id, otherUserId);

    if (outgoing) {
        return res.json({
            status: "outgoing_pending",
            requestId: outgoing.id
        });
    }

    const incoming = db.prepare(`
        SELECT id
        FROM friend_requests
        WHERE sender_id = ?
          AND receiver_id = ?
          AND status = 'pending'
    `).get(otherUserId, currentUser.id);

    if (incoming) {
        return res.json({
            status: "incoming_pending",
            requestId: incoming.id
        });
    }

    res.json({
        status: "none"
    });
});

// ==========================================
// POSTS
// ==========================================

app.post("/api/posts", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const content = (req.body.content || "").trim();

    if (!content) {
        return res.status(400).json({
            error: "Le contenu est vide."
        });
    }

    const result = db.prepare(`
        INSERT INTO posts
        (user_id, content, created_at)
        VALUES (?, ?, datetime('now', 'localtime'))
    `).run(user.id, content);

    res.json({
        success: true,
        postId: result.lastInsertRowid
    });
});

app.get("/api/posts", (req, res) => {
    const posts = db.prepare(`
        SELECT
            posts.id,
            posts.user_id,
            posts.content,
            posts.created_at,
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
            ) AS comments_count

        FROM posts

        JOIN users
        ON users.id = posts.user_id

        ORDER BY posts.id DESC
    `).all();

    res.json(posts);
});

// ==========================================
// LIKE
// ==========================================

app.post("/api/posts/:id/like", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const postId = Number(req.params.id);

    const existingLike = db.prepare(`
        SELECT id
        FROM likes
        WHERE post_id = ?
          AND user_id = ?
    `).get(postId, user.id);

    if (existingLike) {
        db.prepare(`
            DELETE FROM likes
            WHERE post_id = ?
              AND user_id = ?
        `).run(postId, user.id);

        return res.json({
            liked: false
        });
    }

    db.prepare(`
        INSERT INTO likes
        (post_id, user_id)
        VALUES (?, ?)
    `).run(postId, user.id);

    res.json({
        liked: true
    });
});

// ==========================================
// SUPPRIMER POST
// ==========================================

app.delete("/api/posts/:id", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const postId = Number(req.params.id);

    const post = db.prepare(`
        SELECT *
        FROM posts
        WHERE id = ?
    `).get(postId);

    if (!post) {
        return res.status(404).json({
            error: "Publication introuvable."
        });
    }

    if (post.user_id !== user.id) {
        return res.status(403).json({
            error: "Vous ne pouvez pas supprimer cette publication."
        });
    }

    db.prepare(`
        DELETE FROM likes
        WHERE post_id = ?
    `).run(postId);

    db.prepare(`
        DELETE FROM comments
        WHERE post_id = ?
    `).run(postId);

    db.prepare(`
        DELETE FROM posts
        WHERE id = ?
    `).run(postId);

    res.json({
        success: true
    });
});

// ==========================================
// COMMENTAIRES
// ==========================================

app.get("/api/posts/:id/comments", (req, res) => {
    const postId = Number(req.params.id);

    const comments = db.prepare(`
        SELECT
            comments.id,
            comments.post_id,
            comments.user_id,
            comments.content,
            comments.created_at,
            users.name

        FROM comments

        JOIN users
        ON users.id = comments.user_id

        WHERE comments.post_id = ?

        ORDER BY comments.id ASC
    `).all(postId);

    res.json(comments);
});

app.post("/api/posts/:id/comments", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const postId = Number(req.params.id);
    const content = (req.body.content || "").trim();

    if (!content) {
        return res.status(400).json({
            error: "Le commentaire est vide."
        });
    }

    const result = db.prepare(`
        INSERT INTO comments
        (post_id, user_id, content, created_at)
        VALUES (?, ?, ?, datetime('now', 'localtime'))
    `).run(postId, user.id, content);

    res.json({
        success: true,
        commentId: result.lastInsertRowid
    });
});

app.delete("/api/comments/:id", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const commentId = Number(req.params.id);

    const comment = db.prepare(`
        SELECT *
        FROM comments
        WHERE id = ?
    `).get(commentId);

    if (!comment) {
        return res.status(404).json({
            error: "Commentaire introuvable."
        });
    }

    if (comment.user_id !== user.id) {
        return res.status(403).json({
            error: "Vous ne pouvez pas supprimer ce commentaire."
        });
    }

    db.prepare(`
        DELETE FROM comments
        WHERE id = ?
    `).run(commentId);

    res.json({
        success: true
    });
});

// ==========================================
// DEMANDES D'AMIS - ENVOYER
// ==========================================

app.post("/api/friend-requests/:id", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const receiverId = Number(req.params.id);

    if (receiverId === user.id) {
        return res.status(400).json({
            error: "Vous ne pouvez pas vous ajouter vous-même."
        });
    }

    const receiver = db.prepare(`
        SELECT id
        FROM users
        WHERE id = ?
    `).get(receiverId);

    if (!receiver) {
        return res.status(404).json({
            error: "Utilisateur introuvable."
        });
    }

    const alreadyFriends = db.prepare(`
        SELECT id
        FROM friends
        WHERE user_id = ?
          AND friend_id = ?
    `).get(user.id, receiverId);

    if (alreadyFriends) {
        return res.status(400).json({
            error: "Vous êtes déjà amis."
        });
    }

    const existingRequest = db.prepare(`
        SELECT id
        FROM friend_requests
        WHERE sender_id = ?
          AND receiver_id = ?
          AND status = 'pending'
    `).get(user.id, receiverId);

    if (existingRequest) {
        return res.status(400).json({
            error: "Demande déjà envoyée."
        });
    }

    const result = db.prepare(`
        INSERT INTO friend_requests
        (sender_id, receiver_id, status)
        VALUES (?, ?, 'pending')
    `).run(user.id, receiverId);

    // Notification temps réel
    const receiverSocket = onlineUsers.get(receiverId);

    if (receiverSocket) {
        io.to(receiverSocket).emit("friend_request", {
            requestId: result.lastInsertRowid,
            sender: {
                id: user.id,
                name: user.name
            }
        });
    }

    res.json({
        success: true,
        requestId: result.lastInsertRowid
    });
});

// ==========================================
// DEMANDES D'AMIS - LISTE
// ==========================================

app.get("/api/friend-requests", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const requests = db.prepare(`
        SELECT
            friend_requests.id,
            friend_requests.sender_id,
            friend_requests.receiver_id,
            friend_requests.status,
            friend_requests.created_at,
            users.name,
            users.email

        FROM friend_requests

        JOIN users
        ON users.id = friend_requests.sender_id

        WHERE friend_requests.receiver_id = ?
          AND friend_requests.status = 'pending'

        ORDER BY friend_requests.id DESC
    `).all(user.id);

    res.json(requests);
});

// ==========================================
// ACCEPTER DEMANDE
// ==========================================

app.post("/api/friend-requests/:id/accept", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const requestId = Number(req.params.id);

    const request = db.prepare(`
        SELECT *
        FROM friend_requests
        WHERE id = ?
          AND receiver_id = ?
          AND status = 'pending'
    `).get(requestId, user.id);

    if (!request) {
        return res.status(404).json({
            error: "Demande introuvable."
        });
    }

    db.prepare(`
        UPDATE friend_requests
        SET status = 'accepted'
        WHERE id = ?
    `).run(requestId);

    db.prepare(`
        INSERT OR IGNORE INTO friends
        (user_id, friend_id)
        VALUES (?, ?)
    `).run(user.id, request.sender_id);

    db.prepare(`
        INSERT OR IGNORE INTO friends
        (user_id, friend_id)
        VALUES (?, ?)
    `).run(request.sender_id, user.id);

    const senderSocket = onlineUsers.get(request.sender_id);

    if (senderSocket) {
        io.to(senderSocket).emit("friend_request_accepted", {
            userId: user.id,
            name: user.name
        });
    }

    res.json({
        success: true
    });
});

// ==========================================
// REFUSER DEMANDE
// ==========================================

app.post("/api/friend-requests/:id/reject", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const requestId = Number(req.params.id);

    const result = db.prepare(`
        UPDATE friend_requests
        SET status = 'rejected'
        WHERE id = ?
          AND receiver_id = ?
          AND status = 'pending'
    `).run(requestId, user.id);

    if (result.changes === 0) {
        return res.status(404).json({
            error: "Demande introuvable."
        });
    }

    res.json({
        success: true
    });
});

// ==========================================
// AMIS
// ==========================================

app.get("/api/friends", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const friends = db.prepare(`
        SELECT
            users.id,
            users.name,
            users.email

        FROM friends

        JOIN users
        ON users.id = friends.friend_id

        WHERE friends.user_id = ?

        ORDER BY users.name ASC
    `).all(user.id);

    res.json(friends);
});

app.delete("/api/friends/:id", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const friendId = Number(req.params.id);

    db.prepare(`
        DELETE FROM friends
        WHERE user_id = ?
          AND friend_id = ?
    `).run(user.id, friendId);

    db.prepare(`
        DELETE FROM friends
        WHERE user_id = ?
          AND friend_id = ?
    `).run(friendId, user.id);

    res.json({
        success: true
    });
});

// ==========================================
// MESSAGERIE - ENVOYER
// ==========================================

app.post("/api/messages", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const receiverId = Number(req.body.receiver_id);
    const content = (req.body.content || "").trim();

    if (!receiverId || !content) {
        return res.status(400).json({
            error: "Destinataire ou message manquant."
        });
    }

    if (receiverId === user.id) {
        return res.status(400).json({
            error: "Vous ne pouvez pas vous envoyer un message."
        });
    }

    const receiver = db.prepare(`
        SELECT id
        FROM users
        WHERE id = ?
    `).get(receiverId);

    if (!receiver) {
        return res.status(404).json({
            error: "Destinataire introuvable."
        });
    }

    const result = db.prepare(`
        INSERT INTO messages
        (sender_id, receiver_id, content, created_at, is_read)
        VALUES (?, ?, ?, datetime('now', 'localtime'), 0)
    `).run(user.id, receiverId, content);

    // ==========================================
    // NOTIFICATION TEMPS RÉEL
    // ==========================================

    const receiverSocket = onlineUsers.get(receiverId);

    if (receiverSocket) {
        io.to(receiverSocket).emit("new_message", {
            messageId: result.lastInsertRowid,
            senderId: user.id,
            senderName: user.name,
            receiverId: receiverId,
            content: content
        });
    }

    res.json({
        success: true,
        messageId: result.lastInsertRowid
    });
});

// ==========================================
// NOMBRE DE MESSAGES NON LUS
// IMPORTANT : cette route doit être AVANT /:userId
// ==========================================

app.get("/api/messages/unread-count", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const result = db.prepare(`
        SELECT COUNT(*) AS unread_count
        FROM messages
        WHERE receiver_id = ?
          AND is_read = 0
    `).get(user.id);

    res.json({
        unread_count: result.unread_count
    });
});

// ==========================================
// MESSAGERIE - CONVERSATION
// ==========================================

app.get("/api/messages/:userId", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const otherUserId = Number(req.params.userId);

    const otherUser = db.prepare(`
        SELECT id, name, email
        FROM users
        WHERE id = ?
    `).get(otherUserId);

    if (!otherUser) {
        return res.status(404).json({
            error: "Utilisateur introuvable."
        });
    }

    db.prepare(`
        UPDATE messages
        SET is_read = 1
        WHERE sender_id = ?
          AND receiver_id = ?
          AND is_read = 0
    `).run(otherUserId, user.id);

    const messages = db.prepare(`
        SELECT
            messages.id,
            messages.content,
            messages.created_at,
            messages.sender_id,
            messages.receiver_id,
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
                messages.sender_id = ?
                AND messages.receiver_id = ?
            )
            OR
            (
                messages.sender_id = ?
                AND messages.receiver_id = ?
            )

        ORDER BY messages.id ASC
    `).all(
        user.id,
        otherUserId,
        otherUserId,
        user.id
    );

    res.json({
        user: otherUser,
        messages
    });
});

// ==========================================
// MESSAGERIE - CONVERSATIONS
// ==========================================

app.get("/api/conversations", (req, res) => {
    const user = getUserFromToken(req);

    if (!user) {
        return res.status(401).json({
            error: "Non connecté."
        });
    }

    const conversations = db.prepare(`
        SELECT
            u.id,
            u.name,
            u.email,
            m.content AS last_message,
            m.created_at,

            (
                SELECT COUNT(*)
                FROM messages AS unread
                WHERE unread.sender_id = u.id
                  AND unread.receiver_id = ?
                  AND unread.is_read = 0
            ) AS unread_count

        FROM users AS u

        JOIN messages AS m
        ON m.id = (
            SELECT MAX(m2.id)
            FROM messages AS m2
            WHERE
                (
                    m2.sender_id = ?
                    AND m2.receiver_id = u.id
                )
                OR
                (
                    m2.sender_id = u.id
                    AND m2.receiver_id = ?
                )
        )

        WHERE u.id != ?

        ORDER BY m.id DESC
    `).all(
        user.id,
        user.id,
        user.id,
        user.id
    );

    res.json(conversations);
});

// ==========================================
// SERVEUR
// ==========================================

server.listen(PORT, () => {
    console.log(`CommunityOS fonctionne sur http://localhost:${PORT}`);
});