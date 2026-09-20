package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.entity.Product;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ProductService {

    private final ProductRepository productRepository;

    @Transactional(readOnly = true)
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Product getProductById(UUID id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id: " + id));
    }

    @Transactional
    public Product createProduct(Product product) {
        return productRepository.save(product);
    }

    /**
     * Find the product named {@code name}, or create it. Backs the GitHub connector sync, where
     * {@code owner/repo} is the product name and re-syncing the same repo must land on the same
     * product rather than raising a unique-constraint violation on {@code products.name}.
     */
    @Transactional
    public Product findOrCreateByName(String name) {
        return productRepository.findByName(name).orElseGet(() -> {
            Product product = new Product();
            product.setName(name);
            return productRepository.save(product);
        });
    }

    @Transactional
    public void deleteProduct(UUID id) {
        productRepository.deleteById(id);
    }
}