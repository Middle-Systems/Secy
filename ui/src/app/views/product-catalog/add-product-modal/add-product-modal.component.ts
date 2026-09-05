import {Component, EventEmitter, inject, Output} from '@angular/core';
import {FormBuilder, FormGroup, Validators} from '@angular/forms';
import {ProductService} from "../../../services/product.service";
import {MdbModalRef} from "mdb-angular-ui-kit/modal";

@Component({
  selector: 'app-add-product-modal',
  standalone: false,
  templateUrl: './add-product-modal.component.html',
  styleUrl: './add-product-modal.component.scss'
})
export class AddProductModalComponent {
  private fb = inject(FormBuilder);
  private productService = inject(ProductService);
  // Inject the modal reference to allow closing
  public modalRef = inject(MdbModalRef<AddProductModalComponent>);

  productForm = this.fb.group({
    name: ['', [Validators.required, Validators.minLength(3)]],
    description: ['', [Validators.maxLength(500)]]
  });

  isSubmitting = false;

  submitForm(): void {
    if (this.productForm.valid) {
      this.isSubmitting = true;
      this.productService.createProduct(this.productForm.value as any).subscribe({
        next: (newProduct) => {
          this.isSubmitting = false;
          // Close the modal and pass the new product back to the caller
          this.modalRef.close(newProduct);
        },
        error: (err) => {
          console.error('Save failed', err);
          this.isSubmitting = false;
        }
      });
    }
  }
}
