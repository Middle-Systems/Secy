import {Component, inject, OnDestroy, OnInit} from '@angular/core';
import {Product, ProductService} from '../../services/product.service';
import {MdbModalService} from "mdb-angular-ui-kit/modal";
import {AddProductModalComponent} from "./add-product-modal/add-product-modal.component";
import {interval, switchMap} from "rxjs/Observable";
import {Subscription} from "rxjs";
import {UploadSbomModalComponent} from "./upload-sbom-modal/upload-sbom-modal.component";
import {VulnerabilityDetailsComponent} from "./vulnerability-details/vulnerability-details.component";
import {SbomHistoryModalComponent} from "./sbom-history-modal/sbom-history-modal.component";

@Component({
  selector: 'app-product-catalog',
  standalone: false,
  templateUrl: './product-catalog.component.html',
  styleUrls: ['./product-catalog.component.scss']
})
export class ProductCatalogComponent implements OnInit, OnDestroy {
  private productService = inject(ProductService);
  private modalService = inject(MdbModalService);
  products: Product[] = [];

  private pollSubscription?: Subscription;

  ngOnInit(): void {
    this.loadProducts();

    // Check for status updates every 10 seconds
    this.pollSubscription = interval(10000).pipe(
      switchMap(() => this.productService.getProducts())
    ).subscribe(data => {
      this.products = data.map(product => {
        const activeSbom = product.sboms?.find((s: any) => s.active === true);

        // 1. Total Count (Everything found)
        const totalCount = activeSbom?.components?.reduce((sum: number, comp: any) => {
          return sum + (comp.vulnerabilityAlerts?.length || 0);
        }, 0) || 0;

        // 2. Actionable Count (KEV = true OR EPSS > 0.1)
        const actionableCount = activeSbom?.components?.reduce((sum: number, comp: any) => {
          const actionableInComp = comp.vulnerabilityAlerts?.filter((alert: any) => {
            const hasKev = !!alert.vulnerability?.kev;
            const highEpss = (alert.vulnerability?.epss?.epss ?? 0) > 0.1;
            return hasKev || highEpss;
          }).length || 0;
          return sum + actionableInComp;
        }, 0) || 0;

        return {
          ...product,
          activeSbomStatus: activeSbom?.status,
          vulnerabilityCount: totalCount,
          activeSbomId: activeSbom?.id,
          lastScanned: activeSbom?.lastScannedAt,
          actionableCount: actionableCount // New property for the high-risk pill
        };
      });
    });

  }

  ngOnDestroy(): void {
    this.pollSubscription?.unsubscribe();
  }

  openAddProductModal() {
    const modalRef = this.modalService.open(AddProductModalComponent, {
      containerClass: 'modal-lg modal-dialog-centered' // Or any MDB modal class you prefer
    });

    // Handle the result when the modal closes
    modalRef.onClose.subscribe((newProduct) => {
      if (newProduct) {
        this.loadProducts(); // Refresh the list if a product was added
      }
    });
  }

  openUploadModal(product: any) {
    const modalRef = this.modalService.open(UploadSbomModalComponent, {
      data: { product: product } // This passes the product object to the modal
    });

    modalRef.onClose.subscribe((result) => {
      if (result) {
        // Refresh the catalog so the 'Scanning...' status appears immediately
        this.loadProducts();
      }
    });
  }

  openDetailsModal(product: any) {
    const modalRef = this.modalService.open(VulnerabilityDetailsComponent, {
      containerClass: 'modal-lg modal-dialog-centered modal-dialog-scrollable',
      data: { sbomId: product.activeSbomId } // This passes the product object to the modal
    });

    modalRef.onClose.subscribe((result) => {
      if (result) {
        // Refresh the catalog so the 'Scanning...' status appears immediately
        this.loadProducts();
      }
    });
  }

  // Inside your ProductCatalogComponent
  openHistory(product: any): void {
    this.modalService.open(SbomHistoryModalComponent, {
      modalClass: 'modal-lg modal-dialog-centered modal-dialog-scrollable',
      data: { product: product } // This matches the 'product' property in the TS file
    });
  }

  loadProducts(): void {
    this.productService.getProducts().subscribe({
      next: (data) =>{
        this.products = data.map(product => {
          const activeSbom = product.sboms?.find((s: any) => s.active === true);

          // 1. Total Count (Everything found)
          const totalCount = activeSbom?.components?.reduce((sum: number, comp: any) => {
            return sum + (comp.vulnerabilityAlerts?.length || 0);
          }, 0) || 0;

          // 2. Actionable Count (KEV = true OR EPSS > 0.1)
          const actionableCount = activeSbom?.components?.reduce((sum: number, comp: any) => {
            const actionableInComp = comp.vulnerabilityAlerts?.filter((alert: any) => {
              const hasKev = !!alert.vulnerability?.kev;
              const highEpss = (alert.vulnerability?.epss?.epss ?? 0) > 0.1;
              return hasKev || highEpss;
            }).length || 0;
            return sum + actionableInComp;
          }, 0) || 0;

          return {
            ...product,
            activeSbomStatus: activeSbom?.status,
            vulnerabilityCount: totalCount,
            activeSbomId: activeSbom?.id,
            lastScanned: activeSbom?.lastScannedAt,
            actionableCount: actionableCount // New property for the high-risk pill
          };
        });
      },
      error: (err) => console.error('Failed to load products', err)
    });
  }

  copyToClipboard(id: string | undefined): void {
    if (!id) return;

    navigator.clipboard.writeText(id).then(() => {
      // Optional: Add a toast notification or a "Copied!" message
      console.log('Product ID copied to clipboard');
    });
  }
}
