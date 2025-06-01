import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;

public class SimpleBlockchain {
    // Blockchain is a list of blocks
    static ArrayList<Block> blockchain = new ArrayList<>();
    static int difficulty = 4; // Number of leading zeros required for proof-of-work

    // Block class to represent each block in the chain
    static class Block {
        public String hash;
        public String previousHash;
        private String data; // Simplified: represents transaction data (e.g., NFT ownership)
        private long timeStamp;
        private int nonce; // For proof-of-work

        // Constructor
        public Block(String data, String previousHash) {
            this.data = data;
            this.previousHash = previousHash;
            this.timeStamp = new Date().getTime();
            this.hash = calculateHash();
        }

        // Calculate SHA-256 hash of the block
        public String calculateHash() {
            String input = previousHash + Long.toString(timeStamp) + Integer.toString(nonce) + data;
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(input.getBytes("UTF-8"));
                StringBuilder hexString = new StringBuilder();
                for (byte b : hash) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) hexString.append('0');
                    hexString.append(hex);
                }
                return hexString.toString();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        // Mine block: find a hash with required number of leading zeros
        public void mineBlock(int difficulty) {
            String target = new String(new char[difficulty]).replace('\0', '0'); // e.g., "0000"
            while (!hash.substring(0, difficulty).equals(target)) {
                nonce++;
                hash = calculateHash();
            }
            System.out.println("Block mined: " + hash);
        }
    }

    // Add a new block to the chain
    public static void addBlock(Block newBlock) {
        newBlock.mineBlock(difficulty);
        blockchain.add(newBlock);
    }

    // Validate the chain's integrity
    public static boolean isChainValid() {
        Block currentBlock;
        Block previousBlock;

        for (int i = 1; i < blockchain.size(); i++) {
            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i - 1);

            // Verify current block's hash
            if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                System.out.println("Current hash invalid at block " + i);
                return false;
            }

            // Verify previous hash link
            if (!currentBlock.previousHash.equals(previousBlock.hash)) {
                System.out.println("Previous hash mismatch at block " + i);
                return false;
            }
        }
        return true;
    }

    public static void main(String[] args) {
        // Create genesis block (first block)
        Block genesisBlock = new Block("Genesis Block - Music NFT Data", "0");
        addBlock(genesisBlock);

        // Add more blocks (e.g., representing music NFT transactions)
        addBlock(new Block("Artist mints music NFT", genesisBlock.hash));
        addBlock(new Block("Fan buys music NFT", blockchain.get(blockchain.size() - 1).hash));

        // Print the blockchain
        System.out.println("\nBlockchain:");
        for (Block block : blockchain) {
            System.out.println("Data: " + block.data);
            System.out.println("Hash: " + block.hash);
            System.out.println("Previous Hash: " + block.previousHash);
            System.out.println("Timestamp: " + block.timeStamp + "\n");
        }

        // Validate the chain
        System.out.println("Is blockchain valid? " + isChainValid());

        // Test tampering (to demonstrate immutability)
        blockchain.get(1).data = "Tampered NFT Data";
        System.out.println("Is blockchain valid after tampering? " + isChainValid());
    }
}