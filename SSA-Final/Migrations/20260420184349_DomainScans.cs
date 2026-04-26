using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SSA_Final.Migrations
{
    /// <inheritdoc />
    public partial class DomainScans : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DomainScans",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    BaseDomain = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ScannedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DomainScans", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DomainAnalysisResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DomainScanId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Domain = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "bit", nullable: false),
                    Summary = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AnalysedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Indicators = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DomainAnalysisResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DomainAnalysisResults_DomainScans_DomainScanId",
                        column: x => x.DomainScanId,
                        principalTable: "DomainScans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DomainAnalysisResults_DomainScanId",
                table: "DomainAnalysisResults",
                column: "DomainScanId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DomainAnalysisResults");

            migrationBuilder.DropTable(
                name: "DomainScans");
        }
    }
}
