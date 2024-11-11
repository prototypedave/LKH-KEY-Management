#ifndef __INET_LKH_H_
#define __INET_LKH_H_

#include <iostream>
#include <string>
#include <queue>
#include <algorithm>
#include <omnetpp.h>

using namespace std;
using namespace omnetpp;

namespace inet {

/**
 * @desc: Class to define the direction of the members in a binary tree
 * key -> id of the member in the tree
 * pointers: direction of the member in the tree
 */
class Node {
public:
    string key;
    Node* left;
    Node* right;
    Node* parent;

    // Constructor to initialize the node
    Node(string key) : key(key), left(nullptr), right(nullptr), parent(nullptr) {}
};

/**
 * @desc: Tree class to manage the binary tree structure
 */
class Tree {
private:
    // Root node of the tree
    Node* Root;

    /**
     * @brief: gets the number of nodes in a given branch
     */
    int countNodes(Node* node) {
        if (node == nullptr) return 0;
        return 1 + countNodes(node->left) + countNodes(node->right);
    }

    /**
     * @brief: adds a subtree to a branch or node
    */
    void attachSubtree(Node* parent, Node* subtree) {
        if (subtree == nullptr) return;

        queue<Node*> q;
        q.push(parent);

        while (!q.empty()) {
            Node* current = q.front();
            q.pop();

            if (current->left == nullptr) {
                current->left = subtree;
                subtree->parent = current;
                break;
            } else if (current->right == nullptr) {
                current->right = subtree;
                subtree->parent = current;
                break;
            } else {
                q.push(current->left);
                q.push(current->right);
            }
        }
    }


public:
    // Constructor to initialize the root of the tree
    Tree(string key) {
        Root = new Node(key);
    }

    // Getter for the root node
    Node* getRoot() const {
        return Root;
    }

    /**
     * @brief: Adds a node to either the left or right side of the parent
     * @param parent: The parent node where the new node will be added
     * @param key: String value representing the id of the new node
     * @return The newly added node, or nullptr if the parent already has both children
     */
    Node* addNode(Node* parent, Node* newNode) {
        if (parent == nullptr) {
            EV_ERROR << "Parent node is null!" << endl;
            return nullptr;
        }

        newNode->parent = parent;

        if (parent->left == nullptr) {
            parent->left = newNode;
            EV_INFO << newNode->key << " added on the left side of " << parent->key << endl;
            return newNode;
        } else if (parent->right == nullptr) {
            parent->right = newNode;
            EV_INFO << newNode->key << " added on the right side of " << parent->key << endl;
            return newNode;
        } else {
            EV_INFO << parent->key << " already has both left and right children." << endl;
            return nullptr;
        }
    }

    /**
     * @brief: Finds the first node with an empty left or right child
     * @return The first node with an empty child, or nullptr if all nodes are full
     */
    Node* getBranch() {
        if (Root == nullptr) return nullptr;

        queue<Node*> q;
        q.push(Root);

        while (!q.empty()) {
            Node* current = q.front();
            q.pop();

            if (current->left == nullptr || current->right == nullptr) {
                return current;
            }

            if (current->left != nullptr) q.push(current->left);
            if (current->right != nullptr) q.push(current->right);
        }

        return nullptr;
    }

    /**
     * @brief: removes the given node from the tree and updates the tree
     */
    void removeNode(Node* node) {
        if (node == nullptr) {
            EV_ERROR << "Node is null. Cannot restructure." << std::endl;
            return;
        }

        if (node->left == nullptr && node->right == nullptr) {
            if (node->parent) {
                if (node->parent->left == node) {
                    node->parent->left = nullptr;
                } else if (node->parent->right == node) {
                    node->parent->right = nullptr;
                }
            } else {
                Root = nullptr;
            }
            delete node;
            return;
        }

        Node* replacement = (countNodes(node->left) <= countNodes(node->right)) ? node->left : node->right;
            if (replacement != nullptr) {
                replacement->parent = node->parent;
            }

            if (node->parent) {
                if (node->parent->left == node) {
                    node->parent->left = replacement;
                } else if (node->parent->right == node) {
                    node->parent->right = replacement;
                }
            } else {
                Root = replacement;
            }

            if (replacement == node->left && node->right != nullptr) {
                attachSubtree(replacement, node->right);
            } else if (replacement == node->right && node->left != nullptr) {
                attachSubtree(replacement, node->left);
            }

            delete node;
    }

    /**
     * @brief: returns the node if found in the tree
     */
    Node* getNode(const string& key) {
        if (Root == nullptr) return nullptr;

        queue<Node*> q;
        q.push(Root);

        while (!q.empty()) {
            Node* current = q.front();
            q.pop();

            if (current->key == key) {
                return current;
            }

            if (current->left != nullptr) q.push(current->left);
            if (current->right != nullptr) q.push(current->right);
        }

        return nullptr;
    }

    /**
     * @brief: Displays the tree in a simple format (for debugging)
     * @param node: The current node to display
     * @param depth: The depth level (for indentation)
     */
    void displayTree(Node* node, string prefix = "", bool isLeft = true) {
        if (node == nullptr) return;

        // Print the current node with its prefix
        EV << prefix;

        // Determine the connector based on whether it's a left or right child
        EV << (isLeft ? "├── " : "└── ");

        // Print the node's key
        EV << node->key << endl;

        // Prepare the prefix for the next level
        string newPrefix = prefix + (isLeft ? "│   " : "    ");

        // Recurse on the left and right children
        if (node->left || node->right) {
            displayTree(node->left, newPrefix, true);
            displayTree(node->right, newPrefix, false);
        }
    }

    /**
     * @brief: returns a list of keys for the nodes subtree
     */
    vector<string> getPathToNode(Node* node) {
        vector<string> path;
        while (node != nullptr) {
            path.push_back(node->key);
            node = node->parent;
        }
        reverse(path.begin(), path.end());
        return path;
    }
};

} // namespace inet

#endif
