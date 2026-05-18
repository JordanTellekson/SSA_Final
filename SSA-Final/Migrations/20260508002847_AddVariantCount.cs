using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SSA_Final.Migrations
{
    /// <inheritdoc />
    public partial class AddVariantCount : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "VariantCount",
                table: "DomainScans",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "VariantCount",
                table: "DomainScans");
        }
    }
}
