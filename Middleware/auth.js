import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const secretKey = process.env.secretKey;

const authenticate = (req, res, next) => {
    const cookies = req.headers.cookie;
    if (!cookies) {
        return res.status(401).json({ message: "No authentication token found" });
    }

    const cooki = cookies.split(';');

    try {
        for (let cookie of cooki) {
            const [name, token] = cookie.trim().split('=');
            if (name === 'authToken') {
                const verified = jwt.verify(token, secretKey);
                req.username = verified.username;
                req.role = verified.role;
                return next();
            }
        }
        return res.status(401).json({ message: "Authentication token missing or invalid" });
    } catch (error) {
        return res.status(401).json({ message: "Token verification failed", error: error.message });
    }
};

export { authenticate };
