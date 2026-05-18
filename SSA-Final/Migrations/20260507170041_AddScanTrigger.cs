using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SSA_Final.Migrations
{
    /// <inheritdoc />
    public partial class AddScanTrigger : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "ScanTrigger",
                table: "DomainScans",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ScanTrigger",
                table: "DomainScans");
        }
    }
}
