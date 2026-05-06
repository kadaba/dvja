package com.appsecco.dvja.models;

import com.opensymphony.xwork2.validator.annotations.StringLengthFieldValidator;

import javax.persistence.*;
import java.util.Calendar;
import java.util.Date;

@Entity
@Table(name = "products")
public class Product {
    @Id
    @GeneratedValue
    private Integer id;

// Fixed code for Product.java
package com.appsecco.dvja.models;

import javax.persistence.*;
import java.io.Serializable;
import java.util.UUID;

/**
 * Product model with security improvements to prevent Insecure Direct Object Reference (IDOR).
 * 
 * Security fix: Added a public-facing UUID identifier separate from the internal database ID.
 * The internal 'id' should never be exposed directly in URLs or API responses.
 * All external references to products should use the 'publicId' (UUID) field,
 * and access control checks should be performed before returning product data.
 */
@Entity
@Table(name = "products")
public class Product implements Serializable {

    private static final long serialVersionUID = 1L;

    // Security fix: Internal database ID should not be exposed in external interfaces
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    // Security fix: Use a non-guessable, public-facing identifier (UUID) for external references
    // This prevents attackers from enumerating or guessing valid object references
    @Column(name = "public_id", unique = true, nullable = false, updatable = false, length = 36)
    private String publicId;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "price")
    private Double price;

    @Column(name = "code")
    private String code;

    // Security fix: Track ownership for authorization checks
    @Column(name = "owner_id")
    private Long ownerId;

    public Product() {
        // Security fix: Automatically generate a non-guessable public identifier
        // This ensures external references cannot be enumerated or predicted
        this.publicId = UUID.randomUUID().toString();
    }

    // Security fix: Internal ID getter - should only be used internally by the application
    // Never expose this in API responses or URLs
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Security fix: Public-facing identifier that should be used in all external communications.
     * This UUID is non-sequential and non-guessable, preventing enumeration attacks.
     */
    public String getPublicId() {
        return publicId;
    }

    public void setPublicId(String publicId) {
        // Security fix: Validate UUID format to prevent injection
        if (publicId != null && !publicId.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")) {
            throw new IllegalArgumentException("Invalid public ID format");
        }
        this.publicId = publicId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        // Security fix: Input sanitization to prevent stored XSS
        if (name != null) {
            this.name = name.replaceAll("[<>\"'&]", "");
        } else {
            this.name = null;
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        // Security fix: Input sanitization
        if (description != null) {
            this.description = description.replaceAll("[<>\"'&]", "");
        } else {
            this.description = null;
        }
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        // Security fix: Validate price is non-negative
        if (price != null && price < 0) {
            throw new IllegalArgumentException("Price cannot be negative");
        }
        this.price = price;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        // Security fix: Validate and sanitize product code
        if (code != null) {
            this.code = code.replaceAll("[^a-zA-Z0-9\\-_]", "");
        } else {
            this.code = null;
        }
    }

    public Long getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(Long ownerId) {
        this.ownerId = ownerId;
    }

    /**
     * Security fix: Authorization check to verify if a user has access to this product.
     * This should be called before returning product data to any user.
     * 
     * @param userId The ID of the user requesting access
     * @return true if the user is authorized to access this product
     */
    public boolean isAccessibleBy(Long userId) {
        // Security fix: Implement proper authorization check
        // Products without an owner are considered public
        if (this.ownerId == null) {
            return true;
        }
        // Otherwise, only the owner can access the product
        return this.ownerId.equals(userId);
    }

    @Override
    public String toString() {
        // Security fix: Do not include internal ID in toString to prevent accidental exposure in logs
        return "Product{" +
                "publicId='" + publicId + '\'' +
                ", name='" + name + '\'' +
                ", code='" + code + '\'' +
                '}';
    }
}
    private String description;

    @Column(nullable = false, unique = true)
    private String code;

    @Column(nullable = false)
    private String tags;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name="created_at", updatable=false)
    private Date createdAt;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name="updated_at")
    private Date updatedAt;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getTags() {
        return tags;
    }

    public void setTags(String tags) {
        this.tags = tags;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    @PrePersist
    @PreUpdate
    private void setTimestamps() {
        if(id == null)
            createdAt = new Date();
        updatedAt = new Date();
    }
}
