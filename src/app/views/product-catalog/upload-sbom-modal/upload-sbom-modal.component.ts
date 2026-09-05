import {Component, inject} from '@angular/core';
import {MdbModalRef} from "mdb-angular-ui-kit/modal";
import {HttpClient} from "@angular/common/http";

@Component({
  selector: 'app-upload-sbom-modal',
  standalone: false,
  templateUrl: './upload-sbom-modal.component.html',
  styleUrl: './upload-sbom-modal.component.scss'
})
export class UploadSbomModalComponent {
  // Injected by MdbModalService
  product: any;
  productVersion: string = '';

  public modalRef = inject(MdbModalRef<UploadSbomModalComponent>);
  private http = inject(HttpClient);

  selectedFile: File | null = null;
  isUploading = false;

  onFileSelected(event: any): void {
    const file = event.target.files[0];
    if (file && file.type === 'application/json') {
      this.selectedFile = file;
    } else {
      alert('Please select a valid CycloneDX JSON file.');
    }
  }

  upload(): void {
    if (!this.selectedFile) return;

    this.isUploading = true;

    // We read the file as JSON because our backend uses @RequestBody CycloneDXFile
    // If your backend used MultipartFile, we would use FormData here instead.
    const reader = new FileReader();
    reader.onload = (e: any) => {
      const jsonContent = JSON.parse(e.target.result);

      this.http.post(`/api/sbom/${this.product.id}/sboms?productVersion=${this.productVersion}`, jsonContent)
        .subscribe({
          next: (response) => {
            this.isUploading = false;
            this.modalRef.close(response); // Pass response back to refresh catalog
          },
          error: (err) => {
            console.error('Upload failed', err);
            this.isUploading = false;
            alert('Upload failed. Check console for details.');
          }
        });
    };
    reader.readAsText(this.selectedFile);
  }
}
