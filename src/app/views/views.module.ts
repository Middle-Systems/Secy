import {NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {CveDatabaseComponent} from "./cve-database/cve-database.component";
import {DashboardComponent} from "./dashboard/dashboard.component";
import {FormsModule, ReactiveFormsModule} from "@angular/forms";
import {HttpClientModule} from "@angular/common/http";
import {MdbModalModule} from "mdb-angular-ui-kit/modal";
import {IngestModalComponent} from "./cve-database/ingest-modal.component";
import {MdbDropdownModule} from "mdb-angular-ui-kit/dropdown";
import {MdbTooltipModule} from "mdb-angular-ui-kit/tooltip";
import {BaseChartDirective} from "ng2-charts";
import {KevDatabaseComponent} from "./kev-database/kev-database.component";
import {KevRemediationModalComponent} from "./kev-database/kev-remediation-modal/kev-remediation-modal.component";
import {RouterModule} from "@angular/router";
import {EpssDatabaseComponent} from "./epss-database/epss-database.component";
import {ProductCatalogComponent} from "./product-catalog/product-catalog.component";
import {AddProductModalComponent} from "./product-catalog/add-product-modal/add-product-modal.component";
import {UploadSbomModalComponent} from "./product-catalog/upload-sbom-modal/upload-sbom-modal.component";
import {VulnerabilityDetailsComponent} from "./product-catalog/vulnerability-details/vulnerability-details.component";
import {SbomHistoryModalComponent} from "./product-catalog/sbom-history-modal/sbom-history-modal.component";

@NgModule({
  declarations: [CveDatabaseComponent,
    DashboardComponent,
    IngestModalComponent,
    KevDatabaseComponent,
    KevRemediationModalComponent,
    EpssDatabaseComponent,
    ProductCatalogComponent,
    AddProductModalComponent,
    UploadSbomModalComponent,
    VulnerabilityDetailsComponent,
    SbomHistoryModalComponent
  ],
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
    MdbModalModule,
    MdbDropdownModule,
    MdbTooltipModule,
    BaseChartDirective,
    RouterModule
  ]
})
export class ViewsModule {
}
