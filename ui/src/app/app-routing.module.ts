import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import {DashboardComponent} from "./views/dashboard/dashboard.component";
import {LayoutComponent} from "./layout/layout/layout.component";
import {CveDatabaseComponent} from "./views/cve-database/cve-database.component";
import {KevDatabaseComponent} from "./views/kev-database/kev-database.component";
import {EpssDatabaseComponent} from "./views/epss-database/epss-database.component";
import {ProductCatalogComponent} from "./views/product-catalog/product-catalog.component";

const routes: Routes = [
  {
    path: '',
    component: LayoutComponent,
    children: [
      { path: 'dashboard', component: DashboardComponent },
      { path: 'cve-database', component: CveDatabaseComponent },
      { path: 'kev-database', component: KevDatabaseComponent },
      { path: 'epss-database', component: EpssDatabaseComponent },
      { path: 'product-catalog', component: ProductCatalogComponent },
      { path: '', redirectTo: 'dashboard', pathMatch: "full" }
    ]
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
