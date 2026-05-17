using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SSA_Final.Migrations
{
    /// <inheritdoc />
    public partial class AddIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "BaseDomain",
                table: "DomainScans",
                type: "nvarchar(450)",
                maxLength: 450,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "RiskClassification",
                table: "DomainAnalysisResults",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.CreateIndex(
                name: "IX_DomainScans_BaseDomain",
                table: "DomainScans",
                column: "BaseDomain");

            migrationBuilder.CreateIndex(
                name: "IX_DomainScans_CreatedAt",
                table: "DomainScans",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_DomainScans_NumMaliciousDomains",
                table: "DomainScans",
                column: "NumMaliciousDomains");

            migrationBuilder.CreateIndex(
                name: "IX_DomainScans_Status",
                table: "DomainScans",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_DomainAnalysisResults_IsBlocklistMatch",
                table: "DomainAnalysisResults",
                column: "IsBlocklistMatch");

            migrationBuilder.CreateIndex(
                name: "IX_DomainAnalysisResults_IsSuspicious",
                table: "DomainAnalysisResults",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_DomainAnalysisResults_RiskClassification",
                table: "DomainAnalysisResults",
                column: "RiskClassification");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_DomainScans_BaseDomain",
                table: "DomainScans");

            migrationBuilder.DropIndex(
                name: "IX_DomainScans_CreatedAt",
                table: "DomainScans");

            migrationBuilder.DropIndex(
                name: "IX_DomainScans_NumMaliciousDomains",
                table: "DomainScans");

            migrationBuilder.DropIndex(
                name: "IX_DomainScans_Status",
                table: "DomainScans");

            migrationBuilder.DropIndex(
                name: "IX_DomainAnalysisResults_IsBlocklistMatch",
                table: "DomainAnalysisResults");

            migrationBuilder.DropIndex(
                name: "IX_DomainAnalysisResults_IsSuspicious",
                table: "DomainAnalysisResults");

            migrationBuilder.DropIndex(
                name: "IX_DomainAnalysisResults_RiskClassification",
                table: "DomainAnalysisResults");

            migrationBuilder.AlterColumn<string>(
                name: "BaseDomain",
                table: "DomainScans",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)",
                oldMaxLength: 450);

            migrationBuilder.AlterColumn<string>(
                name: "RiskClassification",
                table: "DomainAnalysisResults",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(50)",
                oldMaxLength: 50);
        }
    }
}
