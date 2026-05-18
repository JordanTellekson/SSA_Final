using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SSA_Final.Migrations
{
    /// <inheritdoc />
    public partial class PersistScanLifecycle : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "ScannedAt",
                table: "DomainScans",
                newName: "CreatedAt");

            migrationBuilder.RenameColumn(
                name: "Domain",
                table: "DomainAnalysisResults",
                newName: "DiscoveredDomain");

            migrationBuilder.AddColumn<int>(
                name: "NumMaliciousDomains",
                table: "DomainScans",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "TimeFinished",
                table: "DomainScans",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "NumMaliciousDomains",
                table: "DomainScans");

            migrationBuilder.DropColumn(
                name: "TimeFinished",
                table: "DomainScans");

            migrationBuilder.RenameColumn(
                name: "CreatedAt",
                table: "DomainScans",
                newName: "ScannedAt");

            migrationBuilder.RenameColumn(
                name: "DiscoveredDomain",
                table: "DomainAnalysisResults",
                newName: "Domain");
        }
    }
}
